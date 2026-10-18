// Command rcpreflight checks active candidate Action pins in workflow YAML.
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
	if len(args) != 4 || (args[0] != "all" && args[0] != "candidate") {
		fmt.Fprintln(stderr, "usage: rcpreflight <all|candidate> <commit> <tag> <workflow>")
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

func check(r io.Reader, mode, commit, tag string) error {
	if mode != "all" && mode != "candidate" {
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
	if mode == "candidate" && markers != 1 {
		return fmt.Errorf("expected exactly one candidate marker, got %d", markers)
	}
	found := 0
	inspect := func(n *yaml.Node) error {
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
		if ref != target+"@"+commit {
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
		if err := inspect(job); err != nil {
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
			if err := inspect(step); err != nil {
				return err
			}
		}
	}
	if found == 0 || (mode == "candidate" && found != 1) {
		return fmt.Errorf("expected active candidate uses, got %d", found)
	}
	return nil
}
