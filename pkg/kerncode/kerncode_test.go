package kerncode

import (
	"errors"
	"fmt"
	"testing"
)

func TestCode_ErrorsIsMatchesThroughWrapping(t *testing.T) {
	err := fmt.Errorf("license expired: %w", LicensingTokenExpired)
	if !errors.Is(err, LicensingTokenExpired) {
		t.Fatal("expected errors.Is to match the wrapped Code")
	}
	if errors.Is(err, LicensingTokenMissing) {
		t.Fatal("expected errors.Is to not match a different Code")
	}
}

func TestCode_ErrorStringContainsCode(t *testing.T) {
	err := fmt.Errorf("license key does not match: %w", LicensingSignatureMismatch)
	if got := err.Error(); got != "license key does not match: 0x00_LICENSING_SIGNATURE_MISMATCH" {
		t.Fatalf("unexpected error string: %q", got)
	}
}
