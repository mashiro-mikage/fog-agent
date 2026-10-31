//go:build windows

package directoryjoin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	directoryMutationHelperModeEnv = "FOG_U2_DIRECTORY_MUTEX_HELPER_MODE"
	directoryMutationHelperNameEnv = "FOG_U2_DIRECTORY_MUTEX_NAME"
)

var directoryMutationTestNameCounter uint64

func localDirectoryMutationTestName(t *testing.T) string {
	t.Helper()
	sequence := atomic.AddUint64(&directoryMutationTestNameCounter, 1)
	return fmt.Sprintf(`Local\FOG-U2-test-%d-%d-%d`, os.Getpid(), time.Now().UnixNano(), sequence)
}

func requireDirectoryMutexError(t *testing.T, err error, stage string, waitResult uint32) *DirectoryMutexError {
	t.Helper()
	var got *DirectoryMutexError
	if !errors.As(err, &got) {
		t.Fatalf("error = %T %v, want *DirectoryMutexError stage %q", err, err, stage)
	}
	if got.Stage != stage || got.WaitResult != waitResult {
		t.Fatalf("DirectoryMutexError = %+v, want stage=%q waitResult=0x%x", got, stage, waitResult)
	}
	return got
}

func runDirectoryMutationHelper(t *testing.T, mode, name string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDirectoryMutexHelperProcess$")
	cmd.Env = append(os.Environ(),
		directoryMutationHelperModeEnv+"="+mode,
		directoryMutationHelperNameEnv+"="+name,
	)
	return cmd.CombinedOutput()
}

// TestDirectoryMutexHelperProcess is re-executed as the test.exe helper
// for process contention, abandoned ownership, and panic-cleanup checks.
func TestDirectoryMutexHelperProcess(t *testing.T) {
	mode := os.Getenv(directoryMutationHelperModeEnv)
	if mode == "" {
		return
	}
	name := os.Getenv(directoryMutationHelperNameEnv)
	if !strings.HasPrefix(name, `Local\FOG-U2-test-`) {
		os.Exit(71)
	}

	switch mode {
	case "contend":
		var entered atomic.Bool
		err := withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
			entered.Store(true)
			return nil
		})
		var mutexErr *DirectoryMutexError
		if !entered.Load() && errors.As(err, &mutexErr) && mutexErr.Stage == "timeout" {
			os.Exit(0)
		}
		os.Exit(72)
	case "abandon":
		ops := defaultDirectoryMutexOps()
		h, err := ops.create(name)
		if h == 0 || (err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS)) {
			os.Exit(73)
		}
		result, err := ops.wait(h)
		if err != nil || result != windows.WAIT_OBJECT_0 {
			_ = ops.close(h)
			os.Exit(74)
		}
		// Ending this process while its thread owns the mutex makes the next
		// process observe WAIT_ABANDONED. Deliberately do not release it.
		os.Exit(0)
	case "panic-cleanup":
		ops := directoryMutexOps{
			create: func(string) (windows.Handle, error) { return windows.Handle(1), nil },
			wait:   func(windows.Handle) (uint32, error) { return windows.WAIT_OBJECT_0, nil },
			release: func(windows.Handle) error {
				fmt.Print("PANIC_CLEANUP_RELEASE ")
				return nil
			},
			close: func(windows.Handle) error {
				fmt.Println("PANIC_CLEANUP_CLOSE")
				return nil
			},
		}
		_ = withDirectoryMutationUsing(name, ops, func() error {
			panic("U2 fixture panic")
		})
		os.Exit(75)
	default:
		os.Exit(76)
	}
}

func TestDirectoryMutexUsesOneLockedThreadAcrossYield(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	base := defaultDirectoryMutexOps()
	var mu sync.Mutex
	threadIDs := map[string]uint32{}
	remember := func(stage string) {
		mu.Lock()
		threadIDs[stage] = windows.GetCurrentThreadId()
		mu.Unlock()
	}
	ops := directoryMutexOps{
		create: func(name string) (windows.Handle, error) {
			remember("create")
			return base.create(name)
		},
		wait: func(h windows.Handle) (uint32, error) {
			remember("wait")
			return base.wait(h)
		},
		release: func(h windows.Handle) error {
			remember("release")
			return base.release(h)
		},
		close: func(h windows.Handle) error {
			remember("close")
			return base.close(h)
		},
	}
	err := withDirectoryMutationUsing(name, ops, func() error {
		remember("fn")
		for i := 0; i < 8; i++ {
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withDirectoryMutationUsing: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("owner thread IDs: %v", threadIDs)
	var owner uint32
	for _, stage := range []string{"create", "wait", "fn", "release", "close"} {
		id := threadIDs[stage]
		if id == 0 {
			t.Fatalf("thread ID was not recorded for %s: %v", stage, threadIDs)
		}
		if owner == 0 {
			owner = id
		} else if id != owner {
			t.Fatalf("thread changed at %s: got %d, want owner thread %d (%v)", stage, id, owner, threadIDs)
		}
	}
}

func TestDirectoryMutexOwnerHandoffExcludesCallerThread(t *testing.T) {
	callerReady := make(chan uint32, 1)
	callerReturned := make(chan struct{})
	callbackThread := make(chan uint32, 1)
	allowCallbackReturn := make(chan struct{})
	callbackDone := make(chan struct{})
	callerDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(allowCallbackReturn) }) }
	defer releaseCallback()

	go func() {
		runtime.LockOSThread()
		callerID := windows.GetCurrentThreadId()
		callerReady <- callerID
		runDirectoryOwnerLocked(func() {
			defer close(callbackDone)
			defer runtime.UnlockOSThread()
			callbackThread <- windows.GetCurrentThreadId()
			<-allowCallbackReturn
		}, callerID)
		close(callerReturned)
		close(callerDone)
	}()

	var callerID uint32
	select {
	case callerID = <-callerReady:
	case <-time.After(5 * time.Second):
		t.Fatal("locked caller did not start")
	}
	select {
	case <-callerReturned:
	case <-time.After(5 * time.Second):
		releaseCallback()
		t.Fatal("handoff did not return the original goroutine")
	}
	var callbackID uint32
	select {
	case callbackID = <-callbackThread:
	case <-time.After(5 * time.Second):
		releaseCallback()
		t.Fatal("handoff callback did not start")
	}
	if callerID == 0 || callbackID == 0 || callbackID == callerID {
		t.Fatalf("caller thread=%d, callback thread=%d; callback must use a different OS thread", callerID, callbackID)
	}

	// The caller has returned while the replacement worker is still pinned.
	// Let that callback finish and require its UnlockOSThread cleanup to run.
	releaseCallback()
	select {
	case <-callbackDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handoff callback did not finish its locked-thread cleanup")
	}
	select {
	case <-callerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("original goroutine did not return")
	}
}

func TestDirectoryMutexRejectsConcurrentGoroutine(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	entered := make(chan struct{})
	releaseOwner := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseOwner) })
	ownerDone := make(chan error, 1)
	go func() {
		ownerDone <- withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
			close(entered)
			<-releaseOwner
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		releaseOnce.Do(func() { close(releaseOwner) })
		t.Fatal("first goroutine did not acquire the local mutex")
	}

	var called atomic.Bool
	err := withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
		called.Store(true)
		return nil
	})
	requireDirectoryMutexError(t, err, "timeout", uint32(windows.WAIT_TIMEOUT))
	if called.Load() {
		t.Fatal("second goroutine entered the protected callback")
	}
	releaseOnce.Do(func() { close(releaseOwner) })
	select {
	case err := <-ownerDone:
		if err != nil {
			t.Fatalf("owner returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner did not finish after release")
	}
}

func TestDirectoryMutexRejectsOtherProcess(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	err := withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
		output, childErr := runDirectoryMutationHelper(t, "contend", name)
		if childErr != nil {
			return fmt.Errorf("helper process unexpectedly entered or failed: %w; output=%s", childErr, output)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryMutexRejectsAbandonedThenAllowsReacquire(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	observerOps := defaultDirectoryMutexOps()
	observer, err := observerOps.create(name)
	if observer == 0 || (err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS)) {
		t.Fatalf("create observer handle: handle=%v err=%v", observer, err)
	}
	defer observerOps.close(observer)
	// Keep this unowned handle open so the named mutex survives the helper
	// process. Otherwise its exit destroys the object and the next CreateMutex
	// would observe a fresh, un-abandoned mutex.
	output, err := runDirectoryMutationHelper(t, "abandon", name)
	if err != nil {
		t.Fatalf("helper process failed to abandon mutex: %v; output=%s", err, output)
	}
	var called atomic.Bool
	err = withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
		called.Store(true)
		return nil
	})
	requireDirectoryMutexError(t, err, "abandoned", windows.WAIT_ABANDONED)
	if called.Load() {
		t.Fatal("callback ran after WAIT_ABANDONED")
	}
	if err = withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error { return nil }); err != nil {
		t.Fatalf("mutex was not reusable after abandoned cleanup: %v", err)
	}
}

func TestDirectoryMutexDistinguishesWaitFailures(t *testing.T) {
	tests := []struct {
		name    string
		result  uint32
		waitErr error
		stage   string
	}{
		{name: "timeout", result: uint32(windows.WAIT_TIMEOUT), stage: "timeout"},
		{name: "wait failed", result: windows.WAIT_FAILED, waitErr: errors.New("wait fixture failure"), stage: "wait"},
		{name: "unexpected result", result: 0x42, stage: "unexpected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			closed, released := 0, 0
			var called atomic.Bool
			ops := directoryMutexOps{
				create:  func(string) (windows.Handle, error) { return windows.Handle(1), nil },
				wait:    func(windows.Handle) (uint32, error) { return tc.result, tc.waitErr },
				release: func(windows.Handle) error { released++; return nil },
				close:   func(windows.Handle) error { closed++; return nil },
			}
			err := withDirectoryMutationUsing(localDirectoryMutationTestName(t), ops, func() error {
				called.Store(true)
				return nil
			})
			requireDirectoryMutexError(t, err, tc.stage, tc.result)
			if called.Load() || released != 0 || closed != 1 {
				t.Fatalf("callback called=%v, release count=%d, close count=%d; want callback/release skipped and one close", called.Load(), released, closed)
			}
		})
	}
}

func TestDirectoryMutexReportsCreateReleaseAndCloseErrors(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		createErr := errors.New("create fixture failure")
		waits, closes := 0, 0
		ops := directoryMutexOps{
			create:  func(string) (windows.Handle, error) { return 0, createErr },
			wait:    func(windows.Handle) (uint32, error) { waits++; return windows.WAIT_OBJECT_0, nil },
			release: func(windows.Handle) error { return nil },
			close:   func(windows.Handle) error { closes++; return nil },
		}
		err := withDirectoryMutationUsing(localDirectoryMutationTestName(t), ops, func() error { return nil })
		got := requireDirectoryMutexError(t, err, "create", 0)
		if got.Err != createErr || waits != 0 || closes != 0 {
			t.Fatalf("create error=%v waits=%d closes=%d", got, waits, closes)
		}
	})

	t.Run("release", func(t *testing.T) {
		releaseErr := errors.New("release fixture failure")
		name := localDirectoryMutationTestName(t)
		fnCalls, releaseCalls, closeCalls := 0, 0, 0
		ops := directoryMutexOps{
			create:  func(string) (windows.Handle, error) { return windows.Handle(1), nil },
			wait:    func(windows.Handle) (uint32, error) { return windows.WAIT_OBJECT_0, nil },
			release: func(windows.Handle) error { releaseCalls++; return releaseErr },
			close:   func(windows.Handle) error { closeCalls++; return nil },
		}
		result := make(chan error, 1)
		go func() {
			result <- withDirectoryMutationUsing(name, ops, func() error {
				fnCalls++
				return nil
			})
		}()
		var err error
		select {
		case err = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("withDirectoryMutationUsing did not exit after release failure")
		}
		got := requireDirectoryMutexError(t, err, "release", 0)
		if got.Err != releaseErr || fnCalls != 1 || releaseCalls != 1 || closeCalls != 1 {
			t.Fatalf("error=%v fn=%d release=%d close=%d; want one callback, no replay, and handle close", got, fnCalls, releaseCalls, closeCalls)
		}
	})

	t.Run("close", func(t *testing.T) {
		closeErr := errors.New("close fixture failure")
		fnCalls, releaseCalls := 0, 0
		ops := directoryMutexOps{
			create:  func(string) (windows.Handle, error) { return windows.Handle(1), nil },
			wait:    func(windows.Handle) (uint32, error) { return windows.WAIT_OBJECT_0, nil },
			release: func(windows.Handle) error { releaseCalls++; return nil },
			close:   func(windows.Handle) error { return closeErr },
		}
		err := withDirectoryMutationUsing(localDirectoryMutationTestName(t), ops, func() error {
			fnCalls++
			return nil
		})
		got := requireDirectoryMutexError(t, err, "close", 0)
		if got.Err != closeErr || fnCalls != 1 || releaseCalls != 1 {
			t.Fatalf("error=%v fn=%d release=%d", got, fnCalls, releaseCalls)
		}
	})
}

func TestDirectoryMutexGuardLatchesReleaseFailurePerGuard(t *testing.T) {
	blocked := &atomic.Bool{}
	var creates, waits, releases, closes, fnCalls, nativeCalls atomic.Uint32
	releaseErr := errors.New("guard release fixture failure")
	ops := directoryMutexOps{
		create: func(string) (windows.Handle, error) {
			creates.Add(1)
			return windows.Handle(1), nil
		},
		wait: func(windows.Handle) (uint32, error) {
			waits.Add(1)
			return windows.WAIT_OBJECT_0, nil
		},
		release: func(windows.Handle) error {
			releases.Add(1)
			return releaseErr
		},
		close: func(windows.Handle) error {
			closes.Add(1)
			return nil
		},
	}
	name := localDirectoryMutationTestName(t)
	mutate := func() error {
		fnCalls.Add(1)
		nativeCalls.Add(1)
		return nil
	}

	err := withDirectoryMutationGuard(name, ops, blocked, mutate)
	got := requireDirectoryMutexError(t, err, "release", 0)
	if got.Err != releaseErr || !blocked.Load() || fnCalls.Load() != 1 || nativeCalls.Load() != 1 {
		t.Fatalf("release error=%v blocked=%v fn=%d native=%d; want latched failure after one mutation", got, blocked.Load(), fnCalls.Load(), nativeCalls.Load())
	}
	if creates.Load() != 1 || waits.Load() != 1 || releases.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("first call counts: create=%d wait=%d release=%d close=%d", creates.Load(), waits.Load(), releases.Load(), closes.Load())
	}

	for i := 0; i < 3; i++ {
		err = withDirectoryMutationGuard(name, ops, blocked, mutate)
		requireDirectoryMutexError(t, err, "blocked", 0)
	}
	if creates.Load() != 1 || waits.Load() != 1 || releases.Load() != 1 || closes.Load() != 1 ||
		fnCalls.Load() != 1 || nativeCalls.Load() != 1 {
		t.Fatalf("latched calls reached ops/native: create=%d wait=%d release=%d close=%d fn=%d native=%d",
			creates.Load(), waits.Load(), releases.Load(), closes.Load(), fnCalls.Load(), nativeCalls.Load())
	}

	// A separate guard's process-local latch remains clear and can still run.
	otherBlocked := &atomic.Bool{}
	var otherFnCalls, otherNativeCalls atomic.Uint32
	otherOps := directoryMutexOps{
		create:  func(string) (windows.Handle, error) { return windows.Handle(2), nil },
		wait:    func(windows.Handle) (uint32, error) { return windows.WAIT_OBJECT_0, nil },
		release: func(windows.Handle) error { return nil },
		close:   func(windows.Handle) error { return nil },
	}
	err = withDirectoryMutationGuard(localDirectoryMutationTestName(t), otherOps, otherBlocked, func() error {
		otherFnCalls.Add(1)
		otherNativeCalls.Add(1)
		return nil
	})
	if err != nil || otherBlocked.Load() || otherFnCalls.Load() != 1 || otherNativeCalls.Load() != 1 {
		t.Fatalf("independent guard was affected: err=%v blocked=%v fn=%d native=%d",
			err, otherBlocked.Load(), otherFnCalls.Load(), otherNativeCalls.Load())
	}
}

func TestDirectoryMutexReleaseFailureRetiresThreadAndAbandonsMutex(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	base := defaultDirectoryMutexOps()
	observer, err := base.create(name)
	if observer == 0 || (err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS)) {
		t.Fatalf("create observer handle: handle=%v err=%v", observer, err)
	}
	defer base.close(observer)

	type openedThread struct {
		handle windows.Handle
		err    error
	}
	threadOpened := make(chan openedThread, 1)
	var callbackCalls, releaseCalls atomic.Uint32
	releaseErr := errors.New("intentional release failure")
	ops := base
	ops.release = func(windows.Handle) error {
		releaseCalls.Add(1)
		// Deliberately do not call ReleaseMutex: the pinned worker must exit
		// while it still owns the real mutex.
		return releaseErr
	}
	callErr := withDirectoryMutationUsing(name, ops, func() error {
		callbackCalls.Add(1)
		threadID := windows.GetCurrentThreadId()
		h, openErr := windows.OpenThread(windows.SYNCHRONIZE, false, threadID)
		threadOpened <- openedThread{handle: h, err: openErr}
		return openErr
	})
	var worker openedThread
	select {
	case worker = <-threadOpened:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not publish its worker thread handle")
	}
	if worker.err != nil || worker.handle == 0 {
		t.Fatalf("OpenThread(SYNCHRONIZE) failed: handle=%v err=%v", worker.handle, worker.err)
	}
	defer windows.CloseHandle(worker.handle)
	requireDirectoryMutexError(t, callErr, "release", 0)
	if callbackCalls.Load() != 1 || releaseCalls.Load() != 1 {
		t.Fatalf("callback calls=%d release calls=%d; want exactly one each", callbackCalls.Load(), releaseCalls.Load())
	}
	threadResult, waitErr := windows.WaitForSingleObject(worker.handle, 5000)
	if waitErr != nil || threadResult != windows.WAIT_OBJECT_0 {
		t.Fatalf("owner thread did not terminate after release failure: wait=0x%x err=%v", threadResult, waitErr)
	}

	var abandonedCallback atomic.Uint32
	err = withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error {
		abandonedCallback.Add(1)
		return nil
	})
	requireDirectoryMutexError(t, err, "abandoned", windows.WAIT_ABANDONED)
	if abandonedCallback.Load() != 0 {
		t.Fatal("callback ran after the failed release abandoned the mutex")
	}
	if err = withDirectoryMutationUsing(name, defaultDirectoryMutexOps(), func() error { return nil }); err != nil {
		t.Fatalf("mutex was not reusable after abandoned cleanup: %v", err)
	}
}

func TestDirectoryMutexCleansUpAfterCallbackPanic(t *testing.T) {
	name := localDirectoryMutationTestName(t)
	output, _ := runDirectoryMutationHelper(t, "panic-cleanup", name)
	transcript := string(output)
	if strings.Count(transcript, "PANIC_CLEANUP_RELEASE") != 1 || strings.Count(transcript, "PANIC_CLEANUP_CLOSE") != 1 {
		t.Fatalf("panic path did not release and close before process exit; output=%s", output)
	}
}
