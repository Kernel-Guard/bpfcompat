// Command rcpreflight checks active candidate Action pins and workflow-level
// env bindings in workflow YAML.
// It reads local files only; the shell inventory builds it from vendored code.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const target = "kernel-guard/bpfcompat"
const marker = "bpfcompat-pin: candidate"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run prints VERIFIED or PENDING and returns 0 for a workflow it could judge.
// A usage error or an unreadable file is not a judgement about the workflow:
// it prints nothing to stdout and returns 2, so the caller aborts instead of
// reporting a status.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 4 || (args[0] != "all" && args[0] != "candidate" && args[0] != "env") {
		fmt.Fprintln(stderr, "usage: rcpreflight <all|candidate> <commit> <tag> <workflow>\n       rcpreflight env <name> <value> <workflow>")
		return 2
	}
	// #nosec G304 G703 -- this local CLI intentionally reads the operator-supplied workflow path; it never writes it.
	f, err := os.Open(args[3])
	if err != nil {
		fmt.Fprintln(stderr, "rc-preflight pins:", err)
		return 2
	}
	defer f.Close()
	if err := check(f, args[0], args[1], args[2]); err != nil {
		fmt.Fprintln(stderr, "rc-preflight pins:", err)
		fmt.Fprintln(stdout, "PENDING")
		return 0
	}
	fmt.Fprintln(stdout, "VERIFIED")
	return 0
}

func commentsHave(s, want string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#")) == want {
			return true
		}
	}
	return false
}

// keywords are the workflow keys this checker reads. GitHub matches them
// case-sensitively and has no merge keys, so a case variant or "<<" would be
// ignored here while a YAML tool might honour it: both are rejected.
var keywords = map[string]bool{"jobs": true, "steps": true, "uses": true, "if": true, "env": true}

// validate rejects ambiguous keys and aliases rather than guessing which use
// a runner would execute. Comment markers inside run strings are not comments.
func validate(n *yaml.Node) (int, error) {
	if n.Kind == yaml.AliasNode {
		return 0, fmt.Errorf("YAML aliases require manual verification")
	}
	count := 0
	for _, s := range []string{n.HeadComment, n.LineComment, n.FootComment} {
		for _, line := range strings.Split(s, "\n") {
			if commentsHave(line, marker) {
				count++
			}
		}
	}
	if n.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || keys[k.Value] {
				return 0, fmt.Errorf("non-scalar or duplicate mapping key at line %d", k.Line)
			}
			if k.Value == "<<" || k.Tag == "!!merge" || (keywords[strings.ToLower(k.Value)] && !keywords[k.Value]) {
				return 0, fmt.Errorf("merge or case-variant key %q at line %d", k.Value, k.Line)
			}
			keys[k.Value] = true
		}
	}
	for _, child := range n.Content {
		c, err := validate(child)
		if err != nil {
			return 0, err
		}
		count += c
	}
	return count, nil
}

func field(n *yaml.Node, name string) (*yaml.Node, *yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == name {
				return n.Content[i], n.Content[i+1]
			}
		}
	}
	return nil, nil
}

func asciiEqualFold(a, b string) bool {
	for i := 0; i < len(a); i++ {
		if a[i] >= 0x80 {
			return false
		}
	}
	return strings.EqualFold(a, b)
}

// disabled reports whether a job or step can never run: its if is a literal
// false. Conditions that read a context are the runner's to evaluate and are
// left alone (the canary jobs all depend on their plan job's output).
func disabled(n *yaml.Node) (bool, error) {
	_, cond := field(n, "if")
	if cond == nil {
		return false, nil
	}
	if cond.Kind != yaml.ScalarNode {
		return false, fmt.Errorf("if must be a scalar at line %d", cond.Line)
	}
	v := strings.TrimSpace(cond.Value)
	if strings.HasPrefix(v, "${{") && strings.HasSuffix(v, "}}") {
		v = strings.TrimSpace(v[3 : len(v)-2])
	}
	switch strings.ToLower(v) {
	case "false", "0", "''", "null":
		return true, nil
	}
	return false, nil
}

// checkEnv requires the workflow-level env to bind name to want, and no job or
// step env to rebind it to anything else.
func checkEnv(root, jobs *yaml.Node, name, want string) error {
	binding := func(n *yaml.Node) (*yaml.Node, error) {
		_, env := field(n, "env")
		if env == nil {
			return nil, nil
		}
		if env.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("env must be a mapping at line %d", env.Line)
		}
		_, v := field(env, name)
		if v != nil && v.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s must be a scalar at line %d", name, v.Line)
		}
		return v, nil
	}
	v, err := binding(root)
	if err != nil {
		return err
	}
	if v == nil || v.Value != want {
		return fmt.Errorf("workflow env %s is not %q", name, want)
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		scopes := []*yaml.Node{jobs.Content[i]}
		if _, steps := field(jobs.Content[i], "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			scopes = append(scopes, steps.Content...)
		}
		for _, n := range scopes {
			v, err := binding(n)
			if err != nil {
				return err
			}
			if v != nil && v.Value != want {
				return fmt.Errorf("%s rebound to %q at line %d", name, v.Value, v.Line)
			}
		}
	}
	return nil
}

func check(r io.Reader, mode, commit, tag string) error {
	if mode != "all" && mode != "candidate" && mode != "env" {
		return fmt.Errorf("unknown mode %q", mode)
	}
	d := yaml.NewDecoder(r)
	var doc yaml.Node
	if err := d.Decode(&doc); err != nil {
		return err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected one YAML document")
	}
	markers, err := validate(&doc)
	if err != nil {
		return err
	}
	if len(doc.Content) != 1 {
		return fmt.Errorf("expected workflow mapping")
	}
	_, jobs := field(doc.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("expected jobs mapping")
	}
	if mode == "env" {
		return checkEnv(doc.Content[0], jobs, commit, tag)
	}
	if mode == "candidate" && markers != 1 {
		return fmt.Errorf("expected exactly one candidate marker, got %d", markers)
	}
	found := 0
	inspect := func(n *yaml.Node, jobOff bool) error {
		key, value := field(n, "uses")
		if key == nil {
			return nil
		}
		selected := mode == "candidate" && commentsHave(key.HeadComment+"\n"+value.HeadComment, marker)
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("uses must be a string at line %d", value.Line)
		}
		ref := strings.ToLower(value.Value)
		if mode == "all" {
			selected = ref == target || strings.HasPrefix(ref, target+"@") || strings.HasPrefix(ref, target+"/")
		}
		if !selected {
			return nil
		}
		found++
		off, err := disabled(n)
		if err != nil {
			return err
		}
		if off || jobOff {
			return fmt.Errorf("candidate uses at line %d never runs (if is false)", value.Line)
		}
		// The owner and repository match ASCII case-insensitively, as GitHub
		// resolves them; the commit must be spelled exactly.
		repo, sha, _ := strings.Cut(value.Value, "@")
		if !asciiEqualFold(repo, target) || sha != commit {
			return fmt.Errorf("candidate uses is not @%s at line %d", commit, value.Line)
		}
		note := strings.Fields(strings.TrimPrefix(value.LineComment, "#"))
		if len(note) == 0 || note[0] != tag {
			return fmt.Errorf("candidate uses lacks # %s at line %d", tag, value.Line)
		}
		return nil
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		job := jobs.Content[i]
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("expected job mapping")
		}
		jobOff, err := disabled(job)
		if err != nil {
			return err
		}
		if err := inspect(job, jobOff); err != nil {
			return err
		}
		_, steps := field(job, "steps")
		if steps == nil {
			continue
		}
		if steps.Kind != yaml.SequenceNode {
			return fmt.Errorf("expected steps sequence")
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				return fmt.Errorf("expected step mapping")
			}
			if err := inspect(step, jobOff); err != nil {
				return err
			}
		}
	}
	if found == 0 || (mode == "candidate" && found != 1) {
		return fmt.Errorf("expected active candidate uses, got %d", found)
	}
	return nil
}
