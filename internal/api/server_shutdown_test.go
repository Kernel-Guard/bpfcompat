package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// shutdownTestServer returns a Server bound to a free loopback port with
// anonymous validate enabled and the given fake runner installed.
func shutdownTestServer(t *testing.T, run func(context.Context, runner.Config) (runner.RunResult, error)) *Server {
	t.Helper()
	t.Setenv(envAllowAnonymousValidate, "true")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	s := &Server{cfg: Config{Addr: addr, WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: time.Minute}}
	s.runValidate = run
	t.Cleanup(s.inflight.Wait)
	return s
}

// startServing runs s.serve on a cancellable context, waits until the
// listener answers /livez and returns the cancel func plus serve's result.
func startServing(t *testing.T, s *Server) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx) }()
	t.Cleanup(cancel)
	waitForCondition(t, "server listening", func() bool {
		resp, err := http.Get("http://" + s.cfg.Addr + "/livez")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return cancel, done
}

func startAsyncJob(t *testing.T, s *Server, profileID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, newValidateMultipartRequest(t, "/api/validate/start", profileID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("validate/start: %d %s", rec.Code, rec.Body.String())
	}
	var resp validateStartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode validate/start response: %v", err)
	}
	return resp.JobID
}

// A4-1: serve must not return (and so the process must not exit) while an
// async validate job is still running; it returns once the job finishes.
func TestServeWaitsForInflightAsyncJob(t *testing.T) {
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	defer fake.unblock()
	s := shutdownTestServer(t, fake.run)
	cancel, done := startServing(t, s)

	startAsyncJob(t, s, profileID)
	waitForCondition(t, "async job running", func() bool { return fake.running.Load() == 1 })

	cancel()
	select {
	case err := <-done:
		t.Fatalf("serve returned (err=%v) while an async validate job was still running", err)
	case <-time.After(500 * time.Millisecond):
	}

	fake.unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error after drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the in-flight job finished")
	}
	if fake.running.Load() != 0 {
		t.Fatal("serve returned before the in-flight job finished")
	}
}

// A4-1: a queued async job must not start a new run once shutdown began;
// it ends failed with a clear message instead.
func TestQueuedAsyncJobDoesNotStartAfterShutdown(t *testing.T) {
	t.Setenv(envMaxActiveValidateJobs, "1")
	t.Setenv(envMaxQueuedValidateJobs, "4")
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	defer fake.unblock()
	s := shutdownTestServer(t, fake.run)

	startAsyncJob(t, s, profileID)
	waitForCondition(t, "first job running", func() bool { return fake.running.Load() == 1 })
	queuedID := startAsyncJob(t, s, profileID)
	if st, _ := s.getValidateJob(queuedID); st.State != "queued" {
		t.Fatalf("second job state = %q, want queued", st.State)
	}

	s.shutting.Set(true)
	fake.unblock()

	waitForCondition(t, "queued job terminal", func() bool {
		st, _ := s.getValidateJob(queuedID)
		return st.State == "failed" || st.State == "completed"
	})
	s.inflight.Wait()
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("runner called %d times; the queued job started a run after shutdown began", got)
	}
	st, _ := s.getValidateJob(queuedID)
	if st.State != "failed" {
		t.Fatalf("queued job state = %q, want failed", st.State)
	}
	if !strings.Contains(st.Error, "shut down") || !strings.Contains(st.Error, "resubmit") {
		t.Fatalf("queued job error %q does not explain the shutdown", st.Error)
	}
}

// A4-1: when the drain timeout elapses, running async jobs and sync
// requests get their contexts cancelled (so the runner tears down QEMU and
// overlays) and serve returns only after they unwind.
func TestDrainTimeoutCancelsRunningJobs(t *testing.T) {
	t.Setenv(envShutdownDrainTimeout, "1s")
	profileID := firstProfileIDForAsyncValidateTest(t)
	var running, cancelled atomic.Int32
	s := shutdownTestServer(t, func(ctx context.Context, _ runner.Config) (runner.RunResult, error) {
		running.Add(1)
		defer running.Add(-1)
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			return runner.RunResult{}, ctx.Err()
		case <-time.After(30 * time.Second):
			return runner.RunResult{}, nil
		}
	})
	cancel, done := startServing(t, s)

	jobID := startAsyncJob(t, s, profileID)

	// A synchronous validate over the real loopback listener.
	tmpl := newValidateMultipartRequest(t, "/api/validate", profileID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+s.cfg.Addr+"/api/validate", tmpl.Body)
	if err != nil {
		t.Fatalf("build sync request: %v", err)
	}
	req.Header = tmpl.Header
	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitForCondition(t, "async and sync runs in flight", func() bool { return running.Load() == 2 })

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after the drain timeout")
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("serve returned after %v, before the 1s drain timeout", elapsed)
	}
	if got := cancelled.Load(); got != 2 {
		t.Fatalf("%d of 2 running validations saw their context cancelled at drain timeout", got)
	}
	if running.Load() != 0 {
		t.Fatal("serve returned before cancelled runs unwound")
	}
	if st, _ := s.getValidateJob(jobID); st.State != "failed" {
		t.Fatalf("cancelled async job state = %q, want failed", st.State)
	}
	select {
	case <-syncDone:
	case <-time.After(5 * time.Second):
		t.Fatal("sync validate request did not finish")
	}
}
