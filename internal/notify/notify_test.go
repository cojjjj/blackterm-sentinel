package notify

import (
	"testing"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestShouldNotify(t *testing.T) {
	if !ShouldNotify(model.Event{Severity: "HIGH"}, "medium") {
		t.Fatal("expected HIGH to pass MEDIUM threshold")
	}

	if ShouldNotify(model.Event{Severity: "LOW"}, "medium") {
		t.Fatal("expected LOW to be filtered by MEDIUM threshold")
	}
}

func TestValidMinimum(t *testing.T) {
	for _, level := range []string{"critical", "high", "medium", "low", "info"} {
		if !ValidMinimum(level) {
			t.Fatalf("expected %q to be valid", level)
		}
	}

	if ValidMinimum("banana") {
		t.Fatal("invalid severity was accepted")
	}
}
