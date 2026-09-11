package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DecisionFileName           = "decision.json"
	TestResultFileName         = "test-result.intoto.json"
	VerificationResultFileName = "verification-result.intoto.json"
)

type OutputPaths struct {
	Decision           string
	TestResult         string
	VerificationResult string
}

func WriteEvaluation(outDir string, evaluation Evaluation) (OutputPaths, error) {
	absDir, err := filepath.Abs(outDir)
	if err != nil {
		return OutputPaths{}, fmt.Errorf("resolve conformance output directory: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return OutputPaths{}, fmt.Errorf("create conformance output directory: %w", err)
	}
	paths := OutputPaths{
		Decision:   filepath.Join(absDir, DecisionFileName),
		TestResult: filepath.Join(absDir, TestResultFileName),
	}
	if err := writeJSON(paths.Decision, evaluation.Decision); err != nil {
		return OutputPaths{}, err
	}
	if err := writeJSON(paths.TestResult, evaluation.TestResult); err != nil {
		return OutputPaths{}, err
	}

	verificationPath := filepath.Join(absDir, VerificationResultFileName)
	if evaluation.VerificationResult == nil {
		// This path is owned by this evaluator. Removing it prevents a stale
		// conformant result from surviving a failed or inconclusive re-evaluation.
		if err := os.Remove(verificationPath); err != nil && !os.IsNotExist(err) {
			return OutputPaths{}, fmt.Errorf("remove stale verification result: %w", err)
		}
		return paths, nil
	}
	if err := writeJSON(verificationPath, *evaluation.VerificationResult); err != nil {
		return OutputPaths{}, err
	}
	paths.VerificationResult = verificationPath
	return paths, nil
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conformance JSON: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write conformance JSON %s: %w", path, err)
	}
	return nil
}
