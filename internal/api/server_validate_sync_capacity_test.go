package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// blockingValidateRunner is a fake runner that records how many runs are in
// flight (and the peak) and blocks each run until release is closed or the
// run's context is cancelled.
type blockingValidateRunner struct {
	running atomic.Int32
	peak    atomic.Int32
	calls   atomic.Int32
	release chan struct{}
	once    sync.Once
}

func newBlockingValidateRunner() *blockingValidateRunner {
	return &blockingValidateRunner{release: make(chan struct{})}
}

func (b *blockingValidateRunner) run(ctx context.Context, _ runner.Config) (runner.RunResult, error) {
	b.calls.Add(1)
	n := b.running.Add(1)
	defer b.running.Add(-1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-b.release:
		return runner.RunResult{}, nil
	case <-ctx.Done():
		return runner.RunResult{}, ctx.Err()
	}
}

func (b *blockingValidateRunner) unblock() { b.once.Do(func() { close(b.release) }) }

func newSyncCapacityTestServer(t *testing.T, maxActive, maxQueued int) *Server {
	t.Helper()
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envMaxActiveValidateJobs, strconv.Itoa(maxActive))
	t.Setenv(envMaxQueuedValidateJobs, strconv.Itoa(maxQueued))
	s := &Server{cfg: Config{WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: 2 * time.Minute}}
	t.Cleanup(s.inflight.Wait)
	return s
}

func validateCounts(s *Server) (active, queued int) {
	s.validateJobs.mu.RLock()
	defer s.validateJobs.mu.RUnlock()
	return s.validateJobCountsLocked()
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// RS-2: synchronous POST /api/validate must respect the same max-active /
// max-queued limits as POST /api/validate/start.
func TestSyncValidateRespectsJobCapacity(t *testing.T) {
	const maxActive, maxQueued, total = 2, 3, 9
	s := newSyncCapacityTestServer(t, maxActive, maxQueued)
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	s.runValidate = fake.run
	defer fake.unblock()

	var mu sync.Mutex
	codes := map[int]int{}
	var finished atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
			finished.Add(1)
		}()
	}

	// Steady state: maxActive running, maxQueued waiting, the rest rejected.
	waitForCondition(t, "sync validate steady state", func() bool {
		a, q := validateCounts(s)
		return fake.running.Load() == maxActive && a == maxActive && q == maxQueued &&
			finished.Load() == total-maxActive-maxQueued
	})
	time.Sleep(200 * time.Millisecond) // give any excess run a chance to start
	if got := fake.running.Load(); got > maxActive {
		t.Fatalf("%d sync validate runs in flight, max active is %d", got, maxActive)
	}

	fake.unblock()
	wg.Wait()

	if got := fake.peak.Load(); got > maxActive {
		t.Fatalf("peak concurrent sync validate runs=%d exceeds max active %d", got, maxActive)
	}
	if codes[http.StatusTooManyRequests] != total-maxActive-maxQueued || codes[http.StatusOK] != maxActive+maxQueued {
		t.Fatalf("unexpected status distribution %v (want %d x 200, %d x 429)", codes, maxActive+maxQueued, total-maxActive-maxQueued)
	}
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("capacity leaked after all requests finished: active=%d queued=%d", a, q)
	}
}

// Sync and async validations share one capacity pool in both directions.
func TestSyncAndAsyncValidateShareCapacity(t *testing.T) {
	s := newSyncCapacityTestServer(t, 1, 0)
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	s.runValidate = fake.run
	defer fake.unblock()

	// A running sync validation blocks async submissions.
	syncDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
		syncDone <- rec.Code
	}()
	waitForCondition(t, "sync run to start", func() bool { return fake.running.Load() == 1 })

	startRec := httptest.NewRecorder()
	s.handleValidateStart(startRec, newValidateMultipartRequest(t, "/api/validate/start", profileID))
	if startRec.Code != http.StatusTooManyRequests {
		t.Fatalf("validate/start while a sync run holds the only slot: got %d, want 429 body=%s", startRec.Code, startRec.Body.String())
	}

	fake.unblock()
	if code := <-syncDone; code != http.StatusOK {
		t.Fatalf("sync validate: got %d, want 200", code)
	}
	s.inflight.Wait() // drain any async job admitted by mistake above

	// A running async job blocks sync submissions.
	fake2 := newBlockingValidateRunner()
	s.runValidate = fake2.run
	defer fake2.unblock()
	startRec = httptest.NewRecorder()
	s.handleValidateStart(startRec, newValidateMultipartRequest(t, "/api/validate/start", profileID))
	if startRec.Code != http.StatusAccepted {
		t.Fatalf("validate/start with free capacity: got %d body=%s", startRec.Code, startRec.Body.String())
	}
	waitForCondition(t, "async run to start", func() bool { return fake2.running.Load() == 1 })

	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sync validate while an async job holds the only slot: got %d, want 429 body=%s", rec.Code, rec.Body.String())
	}
	if got := fake2.calls.Load(); got != 1 {
		t.Fatalf("rejected sync validate reached the runner (%d calls)", got)
	}
	fake2.unblock()
	s.inflight.Wait()
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("capacity leaked: active=%d queued=%d", a, q)
	}
}

type failIfReadBody struct{ read atomic.Bool }

func (f *failIfReadBody) Read([]byte) (int, error) {
	f.read.Store(true)
	return 0, errors.New("body must not be read when capacity is exhausted")
}

// A sync validate rejected for capacity must not read (or store) the upload.
func TestSyncValidateCapacityCheckedBeforeBody(t *testing.T) {
	s := newSyncCapacityTestServer(t, 1, 0)
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	s.runValidate = fake.run
	defer fake.unblock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleValidate(httptest.NewRecorder(), newValidateMultipartRequest(t, "/api/validate", profileID))
	}()
	waitForCondition(t, "sync run to start", func() bool { return fake.running.Load() == 1 })

	body := &failIfReadBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/validate", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	rec := httptest.NewRecorder()
	s.handleValidate(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 body=%s", rec.Code, rec.Body.String())
	}
	if body.read.Load() {
		t.Fatalf("request body was read although capacity was exhausted")
	}
	fake.unblock()
	<-done
}

// Slots are released after runner errors, panics, and client cancellation
// (both while running and while queued).
func TestSyncValidateReleasesSlot(t *testing.T) {
	s := newSyncCapacityTestServer(t, 1, 1)
	profileID := firstProfileIDForAsyncValidateTest(t)

	// Runner error.
	s.runValidate = func(context.Context, runner.Config) (runner.RunResult, error) {
		return runner.RunResult{}, errors.New("boom")
	}
	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("runner error: got %d, want 500", rec.Code)
	}
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("slot leaked after runner error: active=%d queued=%d", a, q)
	}

	// Runner panic.
	s.runValidate = func(context.Context, runner.Config) (runner.RunResult, error) {
		panic("runner panic")
	}
	func() {
		defer func() { _ = recover() }()
		s.handleValidate(httptest.NewRecorder(), newValidateMultipartRequest(t, "/api/validate", profileID))
	}()
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("slot leaked after runner panic: active=%d queued=%d", a, q)
	}

	// Client cancellation while running and while queued.
	fake := newBlockingValidateRunner()
	s.runValidate = fake.run
	defer fake.unblock()

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	runDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID).WithContext(runCtx))
		runDone <- rec.Code
	}()
	waitForCondition(t, "first run to start", func() bool { return fake.running.Load() == 1 })

	queueCtx, cancelQueue := context.WithCancel(context.Background())
	defer cancelQueue()
	queueDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID).WithContext(queueCtx))
		queueDone <- rec.Code
	}()
	waitForCondition(t, "second request to queue", func() bool {
		a, q := validateCounts(s)
		return a == 1 && q == 1
	})
	if got := fake.running.Load(); got != 1 {
		t.Fatalf("queued sync request is running: %d runs in flight", got)
	}

	cancelQueue()
	<-queueDone
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("cancelled queued request reached the runner (%d calls)", got)
	}
	if a, q := validateCounts(s); a != 1 || q != 0 {
		t.Fatalf("after queued cancel: active=%d queued=%d, want 1/0", a, q)
	}

	cancelRun()
	<-runDone
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("slot leaked after running request was cancelled: active=%d queued=%d", a, q)
	}

	// Full capacity is available again.
	fake.unblock()
	rec = httptest.NewRecorder()
	s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
	if rec.Code != http.StatusOK {
		t.Fatalf("validate after all releases: got %d body=%s", rec.Code, rec.Body.String())
	}
}

// During graceful shutdown sync validate refuses new work with 503 like
// validate/start, and a queued sync waiter never takes a freed slot.
func TestSyncValidateRefusesDuringShutdown(t *testing.T) {
	s := newSyncCapacityTestServer(t, 1, 1)
	profileID := firstProfileIDForAsyncValidateTest(t)
	fake := newBlockingValidateRunner()
	s.runValidate = fake.run
	defer fake.unblock()

	runDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
		runDone <- rec.Code
	}()
	waitForCondition(t, "first run to start", func() bool { return fake.running.Load() == 1 })

	queueDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
		queueDone <- rec.Code
	}()
	waitForCondition(t, "second request to queue", func() bool {
		_, q := validateCounts(s)
		return q == 1
	})

	s.shutting.Set(true)
	// New submissions are refused before admission.
	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("new sync validate during shutdown: got %d, want 503 body=%s", rec.Code, rec.Body.String())
	}

	// The in-flight run drains; the queued waiter must not start a new run.
	fake.unblock()
	if code := <-runDone; code != http.StatusOK {
		t.Fatalf("in-flight sync validate: got %d, want 200", code)
	}
	if code := <-queueDone; code != http.StatusServiceUnavailable {
		t.Fatalf("queued sync validate during shutdown: got %d, want 503", code)
	}
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("runner called %d times during shutdown, want 1 (only the in-flight run)", got)
	}
	if a, q := validateCounts(s); a != 0 || q != 0 {
		t.Fatalf("capacity leaked after shutdown drain: active=%d queued=%d", a, q)
	}
}
