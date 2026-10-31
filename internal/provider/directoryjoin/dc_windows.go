//go:build windows

package directoryjoin

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindDomainController uses the existing Windows locator, not a machine secret.
func FindDomainController(domain string) (string, error) {
	if domain == "" || len(domain) > 253 {
		return "", errors.New("directory domain unavailable")
	}
	d, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return "", errors.New("invalid directory domain")
	}
	type info struct {
		Name        *uint16
		Address     *uint16
		AddressType uint32
		DomainGUID  windows.GUID
		DomainName  *uint16
		ForestName  *uint16
		Flags       uint32
		DCSite      *uint16
		ClientSite  *uint16
	}
	var result *info
	proc := netapi32Observe.NewProc("DsGetDcNameW")
	status, _, _ := proc.Call(0, uintptr(unsafe.Pointer(d)), 0, 0, 0x40001011, uintptr(unsafe.Pointer(&result)))
	if status != 0 || result == nil {
		return "", errors.New("directory controller discovery failed")
	}
	defer procNetAPIBufferFree.Call(uintptr(unsafe.Pointer(result)))
	name := strings.TrimPrefix(windows.UTF16PtrToString(result.Name), `\\`)
	if !validDCFQDN(name) {
		return "", errors.New("directory controller name invalid")
	}
	return name, nil
}
