package assets

import (
	"testing"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestClassifyByHostname(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"iPhone", "MOBILE"},
		{"iPad", "MOBILE"},
		{"RokuUltra", "IOT"},
		{"RingDoorbell-dc", "IOT"},
		{"LG_Smart_Dryer2_open", "IOT"},
		{"router-main", "NETWORK"},
	}

	for _, tc := range cases {
		if got := Classify(tc.name, nil); got != tc.want {
			t.Fatalf("Classify(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestClassifyByService(t *testing.T) {
	services := []model.Service{
		{Port: 445, Protocol: "tcp", Name: "SMB"},
	}
	if got := Classify("", services); got != "WORKSTATION" {
		t.Fatalf("expected WORKSTATION, got %q", got)
	}
}
