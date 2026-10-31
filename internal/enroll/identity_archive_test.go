package enroll

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

func identityArchivePlan(hostID int) directoryjoin.RejoinPlan {
	return directoryjoin.RejoinPlan{
		Version: 2, Operation: "rebind", ExpectedCurrent: "A", ExpectedPending: "B",
		AttemptID: strings.Repeat("a", 32), HostID: hostID, ConfigRevision: strings.Repeat("b", 32),
		Phase: "ready", Name: "B", Domain: "corp.example", Mode: "existing", DC: "dc.corp.example",
		Target: &directoryjoin.RejoinObject{GUID: "22222222-2222-2222-2222-222222222222", SID: "S-1-5-21-1-2", Account: "B$"},
	}
}

func TestRotateIdentityArchivesVerifiedMarkerByteForByte(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnsureKey(liveID("identity-A")); err != nil {
		t.Fatal(err)
	}
	oldFP, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = 41
	marker := &directoryjoin.Attempt{Version: 1, Fingerprint: oldFP, Plan: validMJ1PlanForHost(41), Phase: "verified"}
	if err = directoryjoin.ReserveAttempt(dir, marker); err != nil {
		t.Fatal(err)
	}
	active := directoryjoin.AttemptPath(dir)
	original, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.RotateIdentity(liveID("identity-A")); err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	if _, err = os.Stat(active); !os.IsNotExist(err) {
		t.Fatalf("active verified marker remains: %v", err)
	}
	digest := sha256.Sum256(original)
	archive := filepath.Join(dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
	archived, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("verified archive missing: %v", err)
	}
	if !bytes.Equal(archived, original) {
		t.Fatal("verified archive did not preserve original marker bytes")
	}
	if _, err = st.KeyFingerprint(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateIdentityPreservesEveryUncertainMarker(t *testing.T) {
	for _, phase := range []string{"unknown", "may_have_run", "awaiting_reboot", "failed", "reserved"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			st, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(liveID("identity-A")); err != nil {
				t.Fatal(err)
			}
			fp, err := st.KeyFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 41
			marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: identityArchivePlan(41), Phase: phase}
			if err = directoryjoin.ReserveAttempt(dir, marker); err != nil {
				t.Fatal(err)
			}
			path := directoryjoin.AttemptPath(dir)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = st.RotateIdentity(liveID("identity-B")); err != nil {
				t.Fatalf("RotateIdentity: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("uncertain marker removed: %v", err)
			}
			got, err := directoryjoin.LoadAttempt(dir)
			if err != nil || got == nil || got.Phase != phase || got.Fingerprint != fp {
				t.Fatalf("marker changed: %+v err=%v", got, err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("uncertain marker bytes changed")
			}
		})
	}
}
