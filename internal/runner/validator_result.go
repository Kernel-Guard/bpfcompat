package runner

import (
	"encoding/json"
	"fmt"
	"os"
)

type validatorResult struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	Host          struct {
		Sysname  string `json:"sysname"`
		Nodename string `json:"nodename"`
		Release  string `json:"release"`
		Version  string `json:"version"`
		Machine  string `json:"machine"`
	} `json:"host"`
	Load struct {
		Status    string `json:"status"`
		ErrorCode int    `json:"error_code"`
		Error     string `json:"error"`
	} `json:"load"`
	Attach struct {
		Mode      string `json:"mode"`
		Status    string `json:"status"`
		Attempted int    `json:"attempted"`
		Passed    int    `json:"passed"`
		Failed    int    `json:"failed"`
	} `json:"attach"`
	Functional struct {
		Status string `json:"status"`
		Tests  []struct {
			Name             string `json:"name"`
			Required         bool   `json:"required"`
			Status           string `json:"status"`
			Command          string `json:"command"`
			TimeoutSeconds   int    `json:"timeout_seconds"`
			ExpectedExitCode int    `json:"expected_exit_code"`
			ExitCode         int    `json:"exit_code"`
			TimedOut         bool   `json:"timed_out"`
			StdoutTail       string `json:"stdout_tail"`
			StderrTail       string `json:"stderr_tail"`
			Error            string `json:"error"`
		} `json:"tests"`
	} `json:"functional"`
	BTF struct {
		KernelBTFAvailable bool `json:"kernel_btf_available"`
		ArtifactHasBTF     bool `json:"artifact_has_btf"`
		ArtifactHasBTFExt  bool `json:"artifact_has_btf_ext"`
	} `json:"btf"`
	Capabilities struct {
		BPFToolAvailable       bool   `json:"bpftool_available"`
		BPFToolProbeOK         bool   `json:"bpftool_probe_ok"`
		BPFToolProbeOutputPath string `json:"bpftool_probe_output_path"`
		MapTypes               struct {
			Ringbuf        probeStatus `json:"ringbuf"`
			PerfEventArray probeStatus `json:"perf_event_array"`
			Array          probeStatus `json:"array"`
			Hash           probeStatus `json:"hash"`
		} `json:"map_types"`
		ProgramTypes struct {
			Tracepoint probeStatus `json:"tracepoint"`
			Kprobe     probeStatus `json:"kprobe"`
			Tracing    probeStatus `json:"tracing"`
			XDP        probeStatus `json:"xdp"`
		} `json:"program_types"`
		AttachPrereqs struct {
			Tracefs          string `json:"tracefs"`
			KprobeEvents     string `json:"kprobe_events"`
			TracepointEvents string `json:"tracepoint_events"`
		} `json:"attach_prereqs"`
	} `json:"capabilities"`
	ProgramVariants []struct {
		Group    string   `json:"group"`
		Chosen   string   `json:"chosen"`
		Disabled []string `json:"disabled"`
	} `json:"program_variants"`
	MapFixups []struct {
		Name              string `json:"name"`
		MaxEntries        string `json:"max_entries"`
		InnerRingbufBytes uint32 `json:"inner_ringbuf_bytes"`
		Status            string `json:"status"`
		Errno             int    `json:"errno"`
		AppliedEntries    uint32 `json:"applied_entries"`
	} `json:"map_fixups"`
	AutoSizedMaps []struct {
		Name       string `json:"name"`
		MapType    uint32 `json:"map_type"`
		MaxEntries uint32 `json:"max_entries"`
	} `json:"auto_sized_maps"`
	Discovery struct {
		Programs []struct {
			Name         string `json:"name"`
			Section      string `json:"section"`
			AttachStatus string `json:"attach_status,omitempty"`
			AttachError  string `json:"attach_error,omitempty"`
			LoadStatus   string `json:"load_status,omitempty"`
			LoadErrno    int    `json:"load_errno,omitempty"`
			LoadLog      string `json:"load_log,omitempty"`
		} `json:"programs"`
	} `json:"discovery"`
	Logs struct {
		Libbpf string `json:"libbpf"`
	} `json:"logs"`
}

type probeStatus struct {
	Status    string `json:"status"`
	ErrorCode int    `json:"error_code"`
	Error     string `json:"error"`
}

func readValidatorResult(path string) (validatorResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return validatorResult{}, fmt.Errorf("read validator result: %w", err)
	}
	var out validatorResult
	if err := json.Unmarshal(data, &out); err != nil {
		return validatorResult{}, fmt.Errorf("parse validator result: %w", err)
	}
	return out, nil
}
