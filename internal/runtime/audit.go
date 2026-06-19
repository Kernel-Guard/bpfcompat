package runtime

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	decisionTraceSchemaVersion = "runtime_decision_trace.v0.1"
	decisionEventSchemaVersion = "runtime_decision_event.v0.1"

	// Decision-event rotation knobs mirror the cloudregistry audit log so a
	// long-running deployment doesn't accumulate an unbounded
	// runtime_decisions.jsonl. The active file rotates to .1 when it exceeds
	// MaxBytes; older rotations evict oldest-first.
	decisionEventMaxBytesEnv         = "BPFCOMPAT_RUNTIME_DECISIONS_MAX_BYTES"
	decisionEventMaxFilesEnv         = "BPFCOMPAT_RUNTIME_DECISIONS_MAX_FILES"
	defaultDecisionEventMaxBytes     = int64(64 << 20)
	defaultDecisionEventMaxFiles     = 10
	defaultDecisionEventScannerLimit = 16 * 1024 * 1024
)

type decisionRotationConfig struct {
	MaxBytes int64
	MaxFiles int
}

func decisionRotationLimits() decisionRotationConfig {
	cfg := decisionRotationConfig{
		MaxBytes: defaultDecisionEventMaxBytes,
		MaxFiles: defaultDecisionEventMaxFiles,
	}
	if raw := strings.TrimSpace(os.Getenv(decisionEventMaxBytesEnv)); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cfg.MaxBytes = n
		}
	}
	if raw := strings.TrimSpace(os.Getenv(decisionEventMaxFilesEnv)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			cfg.MaxFiles = n
		}
	}
	return cfg
}

// rotateDecisionEventStreamIfNeeded keeps the same shape as
// cloudregistry.rotateAuditLogIfNeeded so operators tune both with the same
// mental model. Kept private to runtime to avoid an import cycle.
func rotateDecisionEventStreamIfNeeded(path string, cfg decisionRotationConfig) error {
	if cfg.MaxBytes <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat runtime decision stream: %w", err)
	}
	if info.Size() < cfg.MaxBytes {
		return nil
	}
	maxFiles := cfg.MaxFiles
	if maxFiles < 1 {
		maxFiles = 1
	}
	for i := maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if i == maxFiles-1 {
			if _, err := os.Stat(dst); err == nil {
				if err := os.Remove(dst); err != nil {
					return fmt.Errorf("remove oldest decision rotation %q: %w", dst, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat oldest decision rotation %q: %w", dst, err)
			}
		}
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("stat decision rotation %q: %w", src, err)
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rotate decision %q -> %q: %w", src, dst, err)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate active decision stream to .1: %w", err)
	}
	return nil
}

func decisionShardPaths(basePath string, maxFiles int) []string {
	if maxFiles < 1 {
		maxFiles = 1
	}
	paths := []string{basePath}
	for i := 1; i <= maxFiles; i++ {
		paths = append(paths, fmt.Sprintf("%s.%d", basePath, i))
	}
	return paths
}

type DecisionTrace struct {
	SchemaVersion    string            `json:"schema_version"`
	DecisionID       string            `json:"decision_id"`
	CreatedAt        string            `json:"created_at"`
	Source           string            `json:"source"`
	Operation        string            `json:"operation"`
	WorkDir          string            `json:"workdir"`
	ArtifactName     string            `json:"artifact_name,omitempty"`
	RequestedVersion string            `json:"requested_version,omitempty"`
	TargetProfileID  string            `json:"target_profile_id,omitempty"`
	Policy           *SelectionPolicy  `json:"policy,omitempty"`
	Probe            *ProbeOptions     `json:"probe,omitempty"`
	HostProbe        *HostCapabilities `json:"host_probe,omitempty"`
	Selection        *SelectionResult  `json:"selection,omitempty"`
	Fetch            *FetchResult      `json:"fetch,omitempty"`
	Execution        *ExecuteResult    `json:"execution,omitempty"`
	Status           string            `json:"status"`
	Error            string            `json:"error,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
}

type DecisionEvent struct {
	SchemaVersion    string `json:"schema_version"`
	DecisionID       string `json:"decision_id"`
	CreatedAt        string `json:"created_at"`
	Source           string `json:"source"`
	Operation        string `json:"operation"`
	Status           string `json:"status"`
	ArtifactName     string `json:"artifact_name,omitempty"`
	RequestedVersion string `json:"requested_version,omitempty"`
	SelectedVersion  string `json:"selected_version,omitempty"`
	ExecutionStatus  string `json:"execution_status,omitempty"`
	TracePath        string `json:"trace_path,omitempty"`
}

type DecisionPersistResult struct {
	DecisionID      string        `json:"decision_id"`
	TracePath       string        `json:"trace_path"`
	EventStreamPath string        `json:"event_stream_path"`
	Event           DecisionEvent `json:"event"`
}

func PersistDecisionTrace(workDir string, trace DecisionTrace) (DecisionPersistResult, error) {
	cleanWorkDir := strings.TrimSpace(workDir)
	if cleanWorkDir == "" {
		return DecisionPersistResult{}, fmt.Errorf("workdir is required")
	}
	cleanWorkDir = filepath.Clean(cleanWorkDir)
	trace.WorkDir = cleanWorkDir

	trace.Operation = strings.TrimSpace(strings.ToLower(trace.Operation))
	if trace.Operation == "" {
		return DecisionPersistResult{}, fmt.Errorf("decision operation is required")
	}
	trace.Source = strings.TrimSpace(strings.ToLower(trace.Source))
	if trace.Source == "" {
		trace.Source = "unknown"
	}
	if trace.SchemaVersion == "" {
		trace.SchemaVersion = decisionTraceSchemaVersion
	}
	if trace.Status == "" {
		trace.Status = "success"
	}
	if trace.CreatedAt == "" {
		trace.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if trace.DecisionID == "" {
		suffix, err := randomHex(3)
		if err != nil {
			return DecisionPersistResult{}, fmt.Errorf("generate decision id: %w", err)
		}
		trace.DecisionID = time.Now().UTC().Format("20060102T150405Z") + "-" + suffix
	}
	if trace.ArtifactName == "" {
		trace.ArtifactName = inferArtifactName(trace)
	}

	traceDir := filepath.Join(cleanWorkDir, "runtime-audit", "decisions")
	if err := os.MkdirAll(traceDir, 0o755); err != nil {
		return DecisionPersistResult{}, fmt.Errorf("create runtime decision directory: %w", err)
	}
	tracePath := filepath.Join(traceDir, trace.DecisionID+".json")
	payload, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		return DecisionPersistResult{}, fmt.Errorf("marshal decision trace: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(tracePath, payload, 0o644); err != nil {
		return DecisionPersistResult{}, fmt.Errorf("write decision trace file: %w", err)
	}

	registryDir := filepath.Join(cleanWorkDir, "registry")
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		return DecisionPersistResult{}, fmt.Errorf("create registry directory for runtime decisions: %w", err)
	}
	eventStreamPath := filepath.Join(registryDir, "runtime_decisions.jsonl")
	event := buildDecisionEvent(trace, tracePath)
	line, err := json.Marshal(event)
	if err != nil {
		return DecisionPersistResult{}, fmt.Errorf("marshal decision event: %w", err)
	}
	if err := rotateDecisionEventStreamIfNeeded(eventStreamPath, decisionRotationLimits()); err != nil {
		return DecisionPersistResult{}, fmt.Errorf("rotate runtime decision event stream: %w", err)
	}
	f, err := os.OpenFile(eventStreamPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return DecisionPersistResult{}, fmt.Errorf("open runtime decision event stream: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return DecisionPersistResult{}, fmt.Errorf("append runtime decision event: %w", err)
	}

	return DecisionPersistResult{
		DecisionID:      trace.DecisionID,
		TracePath:       tracePath,
		EventStreamPath: eventStreamPath,
		Event:           event,
	}, nil
}

func ListDecisionEvents(workDir string, limit int) ([]DecisionEvent, error) {
	if strings.TrimSpace(workDir) == "" {
		return nil, fmt.Errorf("workdir is required")
	}
	basePath := filepath.Join(filepath.Clean(workDir), "registry", "runtime_decisions.jsonl")
	paths := decisionShardPaths(basePath, decisionRotationLimits().MaxFiles)
	events := make([]DecisionEvent, 0)
	for _, p := range paths {
		shardEvents, err := readDecisionShard(p)
		if err != nil {
			return nil, err
		}
		events = append(events, shardEvents...)
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CreatedAt == events[j].CreatedAt {
			return events[i].DecisionID > events[j].DecisionID
		}
		return events[i].CreatedAt > events[j].CreatedAt
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func readDecisionShard(path string) ([]DecisionEvent, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open runtime decision event stream %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), defaultDecisionEventScannerLimit)
	events := make([]DecisionEvent, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event DecisionEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("parse runtime decision event line in %q: %w", path, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan runtime decision event stream %q: %w", path, err)
	}
	return events, nil
}

func buildDecisionEvent(trace DecisionTrace, tracePath string) DecisionEvent {
	selectedVersion := ""
	if trace.Selection != nil {
		selectedVersion = strings.TrimSpace(trace.Selection.Selected.ArtifactVersion)
	}
	if selectedVersion == "" && trace.Fetch != nil {
		selectedVersion = strings.TrimSpace(trace.Fetch.ArtifactVersion)
	}
	executionStatus := ""
	if trace.Execution != nil {
		executionStatus = strings.TrimSpace(trace.Execution.Status)
	}

	return DecisionEvent{
		SchemaVersion:    decisionEventSchemaVersion,
		DecisionID:       trace.DecisionID,
		CreatedAt:        trace.CreatedAt,
		Source:           trace.Source,
		Operation:        trace.Operation,
		Status:           trace.Status,
		ArtifactName:     strings.TrimSpace(trace.ArtifactName),
		RequestedVersion: strings.TrimSpace(trace.RequestedVersion),
		SelectedVersion:  selectedVersion,
		ExecutionStatus:  executionStatus,
		TracePath:        tracePath,
	}
}

func inferArtifactName(trace DecisionTrace) string {
	if trace.Selection != nil && strings.TrimSpace(trace.Selection.ArtifactName) != "" {
		return strings.TrimSpace(trace.Selection.ArtifactName)
	}
	if trace.Fetch != nil && strings.TrimSpace(trace.Fetch.ArtifactName) != "" {
		return strings.TrimSpace(trace.Fetch.ArtifactName)
	}
	return ""
}
