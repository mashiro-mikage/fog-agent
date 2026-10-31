package directoryjoin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidDCFQDN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"fqdn", "dc01.corp.example", true},
		{"uppercase", "DC01.CORP.EXAMPLE", true},
		{"single label", "dc01", false},
		{"trailing dot", "dc01.corp.example.", false},
		{"empty label", "dc..example", false},
		{"leading hyphen", "-dc.corp", false},
		{"trailing hyphen", "dc-.corp", false},
		{"underscore", "dc_1.corp", false},
		{"space", "dc 1.corp", false},
		{"command fragment", "dc.corp;Write-Output", false},
		{"ip literal", "192.0.2.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validDCFQDN(tt.in)
			if got != tt.want {
				t.Fatalf("validDCFQDN(%q) = %t, want %t", tt.in, got, tt.want)
			}
		})
	}
}

func TestRejoinObservationJSONIsFlattened(t *testing.T) {
	got, err := json.Marshal(RejoinObservation{
		CurrentName: "B", PendingName: "B-next", Domain: "corp.example",
		Netbios: "CORP", Role: "workstation", SecureChannel: "true",
		Boot: BootObservation{Marker: "boot-id", Started: "2026-10-24T00:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, key := range []string{`"current_name"`, `"pending_name"`, `"secure_channel"`, `"boot"`, `"marker"`, `"started"`} {
		if !strings.Contains(text, key) {
			t.Fatalf("JSON %s does not contain %s", text, key)
		}
	}
	if strings.Contains(text, `"names"`) {
		t.Fatalf("JSON unexpectedly nests names: %s", text)
	}
}
