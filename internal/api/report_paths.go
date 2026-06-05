package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	errReportPathOutsideAllowedRoots   = errors.New("report path is outside allowed roots")
	errManifestPathOutsideAllowedRoots = errors.New("manifest path is outside allowed roots")
)

// resolveServerLocalReportPath validates that a user-supplied report path
// resolves to a real regular file under one of the server's allowed
// report roots (the configured workdir, the sibling "reports" directory
// next to the workdir, or the process CWD's "reports" directory).
//
// It rejects symlink escapes by re-checking containment after
// filepath.EvalSymlinks, and returns a generic error so the response
// does not leak whether the path exists or its real location.
func resolveServerLocalReportPath(workDir, userPath string) (string, error) {
	roots, err := allowedReportRoots(workDir)
	if err != nil {
		return "", err
	}
	return validatePathUnderRoots(userPath, roots, errReportPathOutsideAllowedRoots)
}

// resolveServerLocalManifestPath validates that a manifest path stored on
// a cloud-registry record is server-local before any caller opens it.
// Registry uploads accept manifest_path as a free-text metadata field;
// without this check, an upload-capable principal could direct later
// runtime-execute / policy-load reads to arbitrary files on the server
// (CVE-class: file read via predictable downstream YAML parse).
//
// Allowed roots are the configured server workdir only — manifests for
// hosted artifacts must live inside the project storage tree.
func resolveServerLocalManifestPath(workDir, userPath string) (string, error) {
	roots, err := allowedManifestRoots(workDir)
	if err != nil {
		return "", err
	}
	return validatePathUnderRoots(userPath, roots, errManifestPathOutsideAllowedRoots)
}

func validatePathUnderRoots(userPath string, roots []string, outsideErr error) (string, error) {
	userPath = strings.TrimSpace(userPath)
	if userPath == "" {
		return "", errors.New("path is required")
	}
	abs, err := filepath.Abs(userPath)
	if err != nil {
		return "", outsideErr
	}
	if !pathUnderAnyRoot(abs, roots) {
		return "", outsideErr
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", outsideErr
	}
	if !pathUnderAnyRoot(resolved, roots) {
		return "", outsideErr
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", outsideErr
	}
	if !info.Mode().IsRegular() {
		return "", outsideErr
	}
	return resolved, nil
}

func allowedReportRoots(workDir string) ([]string, error) {
	candidates := []string{}
	workDir = strings.TrimSpace(workDir)
	if workDir != "" {
		if abs, err := filepath.Abs(workDir); err == nil {
			candidates = append(candidates, abs)
			candidates = append(candidates, filepath.Join(filepath.Dir(abs), "reports"))
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "reports"))
	}
	return dedupedResolvedRoots(candidates)
}

func allowedManifestRoots(workDir string) ([]string, error) {
	workDir = strings.TrimSpace(workDir)
	if workDir == "" {
		return nil, fmt.Errorf("workdir required for manifest path validation")
	}
	abs, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("resolve workdir: %w", err)
	}
	return dedupedResolvedRoots([]string{abs})
}

func dedupedResolvedRoots(candidates []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		resolved, err := filepath.EvalSymlinks(c)
		if err != nil {
			resolved = c
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no allowed roots configured")
	}
	return out, nil
}

func pathUnderAnyRoot(target string, roots []string) bool {
	for _, root := range roots {
		if pathUnderRoot(target, root) {
			return true
		}
	}
	return false
}

func pathUnderRoot(target, root string) bool {
	target = filepath.Clean(target)
	root = filepath.Clean(root)
	if target == root {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if strings.HasPrefix(rel, "..") {
		return false
	}
	if filepath.IsAbs(rel) {
		return false
	}
	return true
}
