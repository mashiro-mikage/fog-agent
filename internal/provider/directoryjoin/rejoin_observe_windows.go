//go:build windows

package directoryjoin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	netSetupDomainName   = 3
	dsRoleBasicInfo      = 1
	regOptionVolatile    = 1 // Win32 REG_OPTION_VOLATILE.
	regOpenedExistingKey = 2 // Win32 REG_OPENED_EXISTING_KEY.
	observationTimeout   = 30 * time.Second
)

var (
	netapi32Observe          = syscall.NewLazyDLL("netapi32.dll")
	procNetGetJoinInfo       = netapi32Observe.NewProc("NetGetJoinInformation")
	procNetAPIBufferFree     = netapi32Observe.NewProc("NetApiBufferFree")
	procDsRoleGetPrimaryInfo = netapi32Observe.NewProc("DsRoleGetPrimaryDomainInformation")
	procDsRoleFreeMemory     = netapi32Observe.NewProc("DsRoleFreeMemory")
	kernel32Observe          = syscall.NewLazyDLL("kernel32.dll")
	procGetComputerNameExW   = kernel32Observe.NewProc("GetComputerNameExW")
	advapi32Observe          = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyExW      = advapi32Observe.NewProc("RegCreateKeyExW")
)

const secureChannelScript = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dc = [Console]::In.ReadLine()
if ($null -eq $dc) { [Console]::Error.WriteLine('observation_failed'); exit 2 }
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
    $started = ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
} catch {
    [Console]::Error.WriteLine('observation_failed')
    exit 3
}
$secure = 'unknown'
try {
    $result = Test-ComputerSecureChannel -Server $dc -ErrorAction Stop
    if ($result -is [bool]) {
        if ($result) { $secure = 'true' } else { $secure = 'false' }
    }
} catch {
    $secure = 'unknown'
}
[Console]::Out.WriteLine(('OBS|{0}|{1}' -f $secure, $started))
`

// ObserveRejoin reads the Windows machine name, pending name, directory
// membership, role, secure channel, and current boot. It performs no repair,
// join, rename, or reboot operation.
func ObserveRejoin(dc string) (RejoinObservation, error) {
	if !validDCFQDN(dc) {
		return RejoinObservation{}, errors.New("directory controller must be an ASCII FQDN")
	}

	current, err := os.Hostname()
	if err != nil || current == "" {
		return RejoinObservation{}, errors.New("could not read current computer name")
	}
	pending, err := pendingComputerName()
	if err != nil {
		return RejoinObservation{}, errors.New("could not read pending computer name")
	}
	status, netbios, ok := observeJoinInformation()
	if !ok {
		return RejoinObservation{}, errors.New("could not read Windows domain membership")
	}
	if status != netSetupDomainName {
		netbios = ""
	}
	domain := ""
	if status == netSetupDomainName {
		domain, err = observeDNSDomain()
		if err != nil {
			return RejoinObservation{}, errors.New("could not read Windows DNS domain")
		}
	}
	role := observeMachineRole()
	secure, started, err := observePowerShell(dc)
	if err != nil {
		return RejoinObservation{}, err
	}
	marker, err := bootMarker()
	if err != nil {
		return RejoinObservation{}, errors.New("could not read or create volatile boot marker")
	}

	return RejoinObservation{
		CurrentName: current, PendingName: pending, Domain: domain,
		Netbios: netbios, Role: role, SecureChannel: secure,
		Boot: BootObservation{Marker: marker, Started: started},
	}, nil
}

func observeJoinInformation() (uint32, string, bool) {
	var buf *uint16
	var status uint32
	r, _, _ := procNetGetJoinInfo.Call(0,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&status)))
	if r != 0 {
		return 0, "", false
	}
	name := ""
	if buf != nil {
		name = windows.UTF16PtrToString(buf)
		procNetAPIBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	}
	return status, name, true
}

func observeDNSDomain() (string, error) {
	const computerNameDNSDomain = 2
	var size uint32
	procGetComputerNameExW.Call(computerNameDNSDomain, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "", nil
	}
	buf := make([]uint16, size)
	r, _, _ := procGetComputerNameExW.Call(computerNameDNSDomain,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", errors.New("GetComputerNameExW failed")
	}
	return syscall.UTF16ToString(buf), nil
}

func pendingComputerName() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	value, _, err := k.GetStringValue("NV Hostname")
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	return value, err
}

func observeMachineRole() string {
	var info *struct {
		Role   uint32
		Flags  uint32
		Flat   *uint16
		DNS    *uint16
		Forest *uint16
		GUID   [16]byte
	}
	r, _, _ := procDsRoleGetPrimaryInfo.Call(0, dsRoleBasicInfo,
		uintptr(unsafe.Pointer(&info)))
	if r != 0 || info == nil {
		return "unknown"
	}
	defer procDsRoleFreeMemory.Call(uintptr(unsafe.Pointer(info)))
	role := info.Role
	switch role {
	case 0, 1: // standalone/member workstation
		return "workstation"
	case 3: // member server
		return "member_server"
	case 2: // Workgroup server; only a Join operation may use this role.
		return "standalone_server"
	case 4, 5: // backup/primary domain controller
		return "DC"
	default:
		return "unknown"
	}
}

func observePowerShell(dc string) (string, string, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return "", "", errors.New("PowerShell observation unavailable")
	}
	exe := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(context.Background(), observationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", secureChannelScript)
	cmd.Stdin = strings.NewReader(dc + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		return "", "", errors.New("PowerShell observation failed or timed out")
	}
	line := strings.TrimSuffix(string(out), "\n")
	line = strings.TrimSuffix(line, "\r")
	parts := strings.Split(line, "|")
	if len(parts) != 3 || parts[0] != "OBS" ||
		(parts[1] != "true" && parts[1] != "false" && parts[1] != "unknown") {
		return "", "", errors.New("PowerShell observation returned unexpected output")
	}
	started, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil || started.IsZero() {
		return "", "", errors.New("PowerShell observation returned an invalid boot time")
	}
	return parts[1], started.UTC().Format(time.RFC3339Nano), nil
}

func bootMarker() (string, error) {
	const path = `SOFTWARE\FOGProject\FogAgent\RejoinBoot`
	k, existed, err := createVolatileRegistryKey(path,
		registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	if existed {
		marker, _, err := k.GetStringValue("Marker")
		if err != nil || !validBootMarker(marker) {
			return "", errors.New("volatile boot marker is missing or invalid")
		}
		return marker, nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	marker := fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(raw[0:4]), hex.EncodeToString(raw[4:6]),
		hex.EncodeToString(raw[6:8]), hex.EncodeToString(raw[8:10]),
		hex.EncodeToString(raw[10:16]))
	if err := k.SetStringValue("Marker", marker); err != nil {
		return "", err
	}
	return marker, nil
}

func createVolatileRegistryKey(path string, access uint32) (registry.Key, bool, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false, err
	}
	var key syscall.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyExW.Call(
		uintptr(registry.LOCAL_MACHINE),
		uintptr(unsafe.Pointer(name)),
		0, 0,
		regOptionVolatile,
		uintptr(access),
		0,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return 0, false, syscall.Errno(r)
	}
	return registry.Key(key), disposition == regOpenedExistingKey, nil
}

func validBootMarker(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
