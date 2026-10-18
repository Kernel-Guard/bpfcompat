// Command rcpreflight checks active candidate Action pins, workflow-level env
// bindings and the timed canary schedule in workflow YAML.
// It reads local files only; the shell inventory builds it from vendored code.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	if len(args) != 4 || (args[0] != "all" && args[0] != "candidate" && args[0] != "env" && args[0] != "schedule") {
		fmt.Fprintln(stderr, "usage: rcpreflight <all|candidate> <commit> <tag> <workflow>\n       rcpreflight env <name> <value> <workflow>\n       rcpreflight schedule <published-at> - <workflow>")
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
	resume     = regexp.MustCompile(`(?i)\balways\s*\(|!\s*cancelled\s*\(`)
)

// condition reads the if of a job or step. An if that is empty or YAML null
// is no condition: GitHub runs it as success(). never is true when the
// condition is a constant other than true: it names no context and calls no
// function, so the runner can only ever skip it. GitHub treats false, 0, -0,
// the empty string, null and NaN as false and accepts any JSON number form,
// so every constant except true (keywords are case-insensitive) is treated as
// never running instead of being evaluated here. A condition that reads a
// context or calls a function is the runner's to evaluate (the canary jobs
// all depend on their plan job's output). resumes is true when the condition
// calls always() or !cancelled(), which can run a job after a job it needs
// was skipped; success() and failure() are both false then.
func condition(n *yaml.Node) (never, resumes bool, err error) {
	_, cond := field(n, "if")
	if cond == nil {
		return false, false, nil
	}
	if cond.Kind != yaml.ScalarNode {
		return false, false, fmt.Errorf("if must be a scalar at line %d", cond.Line)
	}
	v := strings.TrimSpace(cond.Value)
	if cond.Tag == "!!null" || v == "" {
		return false, false, nil
	}
	if strings.HasPrefix(v, "${{") && strings.HasSuffix(v, "}}") {
		v = strings.TrimSpace(v[3 : len(v)-2])
	}
	code := quoted.ReplaceAllString(v, "''")
	for _, m := range identifier.FindAllStringSubmatch(code, -1) {
		switch strings.ToLower(m[1]) {
		case "true", "false", "null", "nan", "infinity":
		default:
			return false, resume.MatchString(code), nil
		}
	}
	return !strings.EqualFold(v, "true"), false, nil
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

// needsGraph rejects needs that name no job, the job itself, or a cycle.
func needsGraph(needs map[string][]string, jobs map[string]bool) error {
	state := map[string]int{} // 0 unvisited, 1 on the current path, 2 done
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("needs cycle through job %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, dep := range needs[name] {
			if _, ok := jobs[dep]; !ok {
				return fmt.Errorf("job %q needs unknown job %q", name, dep)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range needs {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

// cronField is one field of a five-field cron line: the values it matches,
// and whether it was "*" (which matters for the day-of-month/day-of-week
// rule).
type cronField struct {
	match [60]bool
	star  bool
}

var cronNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// parseCronField accepts what GitHub documents for schedule crons: *, a
// value, a range a-b, a step */n or a-b/n, comma lists, and JAN-DEC/SUN-SAT
// names. Anything else is refused rather than guessed.
func parseCronField(s string, lo, hi int) (cronField, error) {
	var f cronField
	f.star = s == "*"
	value := func(v string) (int, error) {
		if n, ok := cronNames[strings.ToLower(v)]; ok && hi <= 12 {
			return n, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("cron value %q outside %d-%d", v, lo, hi)
		}
		return n, nil
	}
	for _, part := range strings.Split(s, ",") {
		base, stepText, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepText)
			if err != nil || n < 1 {
				return f, fmt.Errorf("cron step %q", part)
			}
			step = n
		}
		first, last := lo, hi
		switch a, b, isRange := strings.Cut(base, "-"); {
		case base == "*":
		case isRange:
			var err error
			if first, err = value(a); err != nil {
				return f, err
			}
			if last, err = value(b); err != nil {
				return f, err
			}
			if first > last {
				return f, fmt.Errorf("cron range %q", part)
			}
		case hasStep:
			return f, fmt.Errorf("cron step needs * or a range: %q", part)
		default:
			n, err := value(base)
			if err != nil {
				return f, err
			}
			first, last = n, n
		}
		for n := first; n <= last; n += step {
			f.match[n] = true
		}
	}
	return f, nil
}

type cronSpec [5]cronField

func parseCron(line string) (cronSpec, error) {
	var c cronSpec
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return c, fmt.Errorf("cron %q does not have 5 fields", line)
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i, field := range fields {
		f, err := parseCronField(field, bounds[i][0], bounds[i][1])
		if err != nil {
			return c, err
		}
		c[i] = f
	}
	if c[4].match[7] {
		c[4].match[0] = true // 7 is Sunday too
	}
	return c, nil
}

// fires reports whether the cron fires at minute t (UTC). As in cron, when
// both day of month and day of week are restricted either one may match.
func (c *cronSpec) fires(t time.Time) bool {
	if !c[0].match[t.Minute()] || !c[1].match[t.Hour()] || !c[3].match[int(t.Month())] {
		return false
	}
	dom, dow := c[2].match[t.Day()], c[4].match[int(t.Weekday())]
	if c[2].star || c[4].star {
		return dom && dow
	}
	return dom || dow
}

// checkSchedule requires the workflow's on.schedule to fire inside each timed
// canary window the plan job accepts: 20-30 and 68-78 whole hours after
// publication, that is [T0+20h, T0+31h) and [T0+68h, T0+79h). A cron firing
// at the window's start leaves no room for schedule delay; that margin is the
// operator's choice and is not judged here.
func checkSchedule(root *yaml.Node, published string) error {
	t0, err := time.Parse(time.RFC3339, published)
	if err != nil {
		return fmt.Errorf("publication time %q: %w", published, err)
	}
	_, on := field(root, "on")
	if on == nil {
		return fmt.Errorf("no on.schedule list")
	}
	_, schedule := field(on, "schedule")
	if schedule == nil || schedule.Kind != yaml.SequenceNode {
		return fmt.Errorf("no on.schedule list")
	}
	var crons []cronSpec
	for _, item := range schedule.Content {
		_, line := field(item, "cron")
		if line == nil || line.Kind != yaml.ScalarNode {
			return fmt.Errorf("schedule entry without a cron string at line %d", item.Line)
		}
		c, err := parseCron(line.Value)
		if err != nil {
			return err
		}
		crons = append(crons, c)
	}
	for _, w := range [][2]int{{20, 31}, {68, 79}} {
		start, end := t0.UTC().Add(time.Duration(w[0])*time.Hour), t0.UTC().Add(time.Duration(w[1])*time.Hour)
		t := start.Truncate(time.Minute)
		if t.Before(start) {
			t = t.Add(time.Minute)
		}
		found := false
		for ; t.Before(end) && !found; t = t.Add(time.Minute) {
			for i := range crons {
				found = found || crons[i].fires(t)
			}
		}
		if !found {
			return fmt.Errorf("no schedule cron fires in [T0+%dh, T0+%dh)", w[0], w[1])
		}
	}
	return nil
}

func check(r io.Reader, mode, commit, tag string) error {
	if mode != "all" && mode != "candidate" && mode != "env" && mode != "schedule" {
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
	if mode == "schedule" {
		return checkSchedule(doc.Content[0], commit)
	}
	_, jobs := field(doc.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("expected jobs mapping")
	}
	// A job can never run when its own if is a constant other than true, or
	// when a job it needs can never run and its if does not resume after a
	// skipped need. Job IDs compare case-insensitively, as GitHub resolves
	// needs; a needs graph GitHub would reject is rejected here too.
	never, resumes, needs := map[string]bool{}, map[string]bool{}, map[string][]string{}
	for i := 0; i < len(jobs.Content); i += 2 {
		name, job := strings.ToLower(jobs.Content[i].Value), jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("expected job mapping")
		}
		if _, dup := never[name]; dup {
			return fmt.Errorf("job IDs differ only by case at line %d", jobs.Content[i].Line)
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
			needs[name] = []string{strings.ToLower(n.Value)}
		case n.Kind == yaml.SequenceNode:
			for _, dep := range n.Content {
				if dep.Kind != yaml.ScalarNode {
					return fmt.Errorf("needs must list job names at line %d", dep.Line)
				}
				needs[name] = append(needs[name], strings.ToLower(dep.Value))
			}
		default:
			return fmt.Errorf("needs must be a job name or a list at line %d", n.Line)
		}
	}
	if err := needsGraph(needs, never); err != nil {
		return err
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
		name, job := strings.ToLower(jobs.Content[i].Value), jobs.Content[i+1]
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
