//go:build windows

package directoryjoin

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// Go runs package initialization on its startup OS thread. That thread is
// parked, rather than terminated, when a locked goroutine exits (runtime m0).
// Never acquire a mutation mutex there: a failed release must be able to retire
// the owner thread without returning it to Go's scheduler.
var directoryStartupThreadID = windows.GetCurrentThreadId()

func startDirectoryOwner(fn func()) {
	go func() {
		runtime.LockOSThread()
		runDirectoryOwnerLocked(fn, directoryStartupThreadID)
	}()
}

// The caller owns one LockOSThread level; fn owns its corresponding cleanup.
func runDirectoryOwnerLocked(fn func(), excludedThreadID uint32) {
	if windows.GetCurrentThreadId() == excludedThreadID {
		ready := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			close(ready)
			fn()
		}()
		// Keep m0 occupied until the replacement owns a different thread.
		<-ready
		runtime.UnlockOSThread()
		return
	}
	fn()
}

// DirectoryMutexError describes the lock failure, not the native AD outcome.
type DirectoryMutexError struct {
	Stage      string
	WaitResult uint32
	Err        error
}

func (e *DirectoryMutexError) Error() string {
	return fmt.Sprintf("directory mutex %s (wait=0x%08x): %v", e.Stage, e.WaitResult, e.Err)
}

func (e *DirectoryMutexError) Unwrap() error { return e.Err }

type directoryMutexOps struct {
	create  func(string) (windows.Handle, error)
	wait    func(windows.Handle) (uint32, error)
	release func(windows.Handle) error
	close   func(windows.Handle) error
}

func defaultDirectoryMutexOps() directoryMutexOps {
	return directoryMutexOps{
		create: func(name string) (windows.Handle, error) {
			n, err := windows.UTF16PtrFromString(name)
			if err != nil {
				return 0, err
			}
			return windows.CreateMutex(nil, false, n)
		},
		wait:    func(h windows.Handle) (uint32, error) { return windows.WaitForSingleObject(h, 0) },
		release: windows.ReleaseMutex,
		close:   windows.CloseHandle,
	}
}

func withDirectoryMutation(fn func() error) error {
	return withDirectoryMutationGuard(`Global\FOG-Agent-DirectoryJoin`, defaultDirectoryMutexOps(), &directoryMutationBlocked, fn)
}

// A release failure also blocks legacy calls, which do not own a directory attempt marker.
// This is a process-local safety latch, not a persisted operation authority.
var directoryMutationBlocked atomic.Bool

func withDirectoryMutationGuard(name string, ops directoryMutexOps, blocked *atomic.Bool, fn func() error) error {
	if blocked.Load() {
		return &DirectoryMutexError{Stage: "blocked", Err: errors.New("a previous mutex release failed; review required")}
	}
	release := ops.release
	ops.release = func(h windows.Handle) error {
		err := release(h)
		if err != nil {
			// Set before closing the owner handle so another caller cannot
			// acquire a newly created mutex and dispatch a second mutation.
			blocked.Store(true)
		}
		return err
	}
	return withDirectoryMutationUsing(name, ops, func() error {
		if blocked.Load() {
			return &DirectoryMutexError{Stage: "blocked", Err: errors.New("a previous mutex release failed; review required")}
		}
		return fn()
	})
}

// The callback and all ownership cleanup run on one dedicated OS thread.
// A failed ReleaseMutex leaves ownership uncertain: exiting a still-locked
// goroutine retires that OS thread rather than returning an owner to the pool.
// The caller receives the error once; this helper never repeats the callback.
func withDirectoryMutationUsing(name string, ops directoryMutexOps, fn func() error) error {
	type outcome struct {
		err   error
		panic any
	}
	done := make(chan outcome, 1)
	startDirectoryOwner(func() {
		var result outcome
		var h windows.Handle
		owned, retire, started, completed := false, false, false, false
		defer func() {
			result.panic = recover()
			if started && !completed && result.panic == nil {
				result.err = errors.Join(result.err, &DirectoryMutexError{Stage: "callback", Err: errors.New("callback exited without a result")})
			}
			if owned {
				if err := ops.release(h); err != nil {
					retire = true
					result.err = errors.Join(result.err, &DirectoryMutexError{Stage: "release", Err: err})
				}
			}
			if h != 0 {
				if err := ops.close(h); err != nil {
					result.err = errors.Join(result.err, &DirectoryMutexError{Stage: "close", Err: err})
				}
			}
			if !retire {
				runtime.UnlockOSThread()
			}
			done <- result
		}()
		var err error
		h, err = ops.create(name)
		if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) || h == 0 {
			result.err = &DirectoryMutexError{Stage: "create", Err: err}
			return
		}
		wait, err := ops.wait(h)
		if err != nil || wait == windows.WAIT_FAILED {
			result.err = &DirectoryMutexError{Stage: "wait", WaitResult: wait, Err: err}
			return
		}
		switch wait {
		case windows.WAIT_OBJECT_0:
			owned = true
		case windows.WAIT_ABANDONED:
			owned = true
			result.err = &DirectoryMutexError{Stage: "abandoned", WaitResult: wait, Err: errors.New("previous mutation owner exited; review required")}
			return
		case uint32(windows.WAIT_TIMEOUT):
			result.err = &DirectoryMutexError{Stage: "timeout", WaitResult: wait, Err: errors.New("another directory mutation owns the mutex")}
			return
		default:
			result.err = &DirectoryMutexError{Stage: "unexpected", WaitResult: wait, Err: errors.New("unexpected mutex wait result")}
			return
		}
		started = true
		result.err = fn()
		completed = true
	})
	result := <-done
	if result.panic != nil {
		panic(result.panic)
	}
	return result.err
}
