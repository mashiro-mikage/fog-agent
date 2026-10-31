//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func allowIdentityReset() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("identity reset requires an elevated administrator")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State != svc.Stopped {
		return errors.New("stop fog-agent before resetting its identity")
	}
	return nil
}
