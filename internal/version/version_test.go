package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	if Version != "v0.6.0" {
		t.Errorf("expected Version to be v0.6.0, got %s", Version)
	}

	formatted := Formatted()
	if !strings.Contains(formatted, "v0.6.0") {
		t.Errorf("expected Formatted() to contain v0.6.0, got %s", formatted)
	}

	// Verify consistency with root VERSION file
	data, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err == nil {
		rootVer := strings.TrimSpace(string(data))
		if Version != rootVer {
			t.Errorf("Version in code (%s) does not match VERSION file (%s)", Version, rootVer)
		}
	}
}
