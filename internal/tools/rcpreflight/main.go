// Command rcpreflight checks active candidate Action pins and workflow-level
// env bindings in workflow YAML.
// It reads local files only; the shell inventory builds it from vendored code.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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
// case-sensitively, so a case variant would be ignored here while a YAML tool
// might honour it. They are checked only where GitHub reads its own keywords
// (the workflow, each job and each step); env names, inputs and matrix keys
// are user data and may be spelled any way. Merge keys ("<<"), which GitHub
// does not support, are rejected everywhere.
var keywords = map[string]bool{"jobs": true, "steps": true, "uses": true, "if": true, "env": true, "needs": true}

func keywordCase(n *yaml.Node) error {
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i].Value; keywords[strings.ToLower(k)] && !keywords[k] {
			return fmt.Errorf("case-variant key %q at line %d", k, n.Content[i].Line)
		}
	}
	return nil
}

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
			if k.Value == "<<" || k.Tag == "!!merge" {
				return 0, fmt.Errorf("merge key at line %d", k.Line)
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

var (
	quoted     = regexp.MustCompile(`'(?:[^']|'')*'`)
	identifier = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_-]*)`)
	resume     = regexp.MustCompile(`(?i)\b(?:always|failure|cancelled)\s*\(`)
)

// condition reads the if of a job or step. never is true when the condition
// is a constant other than true: it names no context and calls no function,
// so the runner can only ever skip it. GitHub treats false, 0, -0, ”, null
// and NaN as false and accepts any JSON number form, so every constant except
// the literal true is treated as never running instead of being evaluated
// here. Conditions that read a context are the runner's to evaluate (the
// canary jobs all depend on their plan job's output). resumes is true when
// the condition calls always(), failure() or cancelled(), which let a job run
// after a job it needs was skipped.
func condition(n *yaml.Node) (never, resumes bool, err error) {
	_, cond := field(n, "if")
	if cond == nil {
		return false, false, nil
	}
	if cond.Kind != yaml.ScalarNode {
		return false, false, fmt.Errorf("if must be a scalar at line %d", cond.Line)
	}
	v := strings.TrimSpace(cond.Value)
	if strings.HasPrefix(v, "${{") && strings.HasSuffix(v, "}}") {
		v = strings.TrimSpace(v[3 : len(v)-2])
	}
	for _, m := range identifier.FindAllStringSubmatch(quoted.ReplaceAllString(v, "''"), -1) {
		switch strings.ToLower(m[1]) {
		case "true", "false", "null", "nan", "infinity":
		default:
			return false, resume.MatchString(v), nil
		}
	}
	return v != "true", false, nil
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
	if v == nil {
		return fmt.Errorf("absent from the workflow env")
	}
	if v.Value != want {
		return fmt.Errorf("%q in the workflow env", v.Value)
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
				return fmt.Errorf("rebound to %q at line %d", v.Value, v.Line)
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
	if err := keywordCase(doc.Content[0]); err != nil {
		return err
	}
	_, jobs := field(doc.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("expected jobs mapping")
	}
	// A job can never run when its own if is a constant other than true, or
	// when a job it needs can never run and its if does not resume after a
	// skipped need.
	never, resumes, needs := map[string]bool{}, map[string]bool{}, map[string][]string{}
	for i := 0; i < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("expected job mapping")
		}
		if err := keywordCase(job); err != nil {
			return err
		}
		if _, steps := field(job, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for _, step := range steps.Content {
				if err := keywordCase(step); err != nil {
					return err
				}
			}
		}
		off, res, err := condition(job)
		if err != nil {
			return err
		}
		never[name], resumes[name] = off, res
		switch _, n := field(job, "needs"); {
		case n == nil:
		case n.Kind == yaml.ScalarNode:
			needs[name] = []string{n.Value}
		case n.Kind == yaml.SequenceNode:
			for _, dep := range n.Content {
				if dep.Kind != yaml.ScalarNode {
					return fmt.Errorf("needs must list job names at line %d", dep.Line)
				}
				needs[name] = append(needs[name], dep.Value)
			}
		default:
			return fmt.Errorf("needs must be a job name or a list at line %d", n.Line)
		}
	}
	for changed := true; changed; {
		changed = false
		for name, deps := range needs {
			for _, dep := range deps {
				if !never[name] && !resumes[name] && never[dep] {
					never[name], changed = true, true
				}
			}
		}
	}
	if mode == "env" {
		return checkEnv(doc.Content[0], jobs, commit, tag)
	}
	if mode == "candidate" && markers != 1 {
		return fmt.Errorf("expected exactly one candidate marker, got %d", markers)
	}
	found := 0
	inspect := func(n *yaml.Node, off bool) error {
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
		if off {
			return fmt.Errorf("candidate uses at line %d can never run (a constant if other than true, here or on a needed job)", value.Line)
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
	for i := 0; i < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		if err := inspect(job, never[name]); err != nil {
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
			off, _, err := condition(step)
			if err != nil {
				return err
			}
			if err := inspect(step, off || never[name]); err != nil {
				return err
			}
		}
	}
	if found == 0 || (mode == "candidate" && found != 1) {
		return fmt.Errorf("expected active candidate uses, got %d", found)
	}
	return nil
}
