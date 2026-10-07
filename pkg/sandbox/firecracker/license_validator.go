package firecracker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"secops-kernel/pkg/kerncode"
)

type CommercialLicense struct {
	OEMVendorID    string
	LicenseKey     string
	ExpirationTime time.Time
	GracePeriodMs  int64
}

type LicenseValidator struct {
	secretKey []byte
}

// LicenseSecretEnvVar is the environment variable NewLicenseValidatorFromEnv
// reads the HMAC signing key from.
//
// Previously this key was a literal string ("enterprise_secret_salt_2026")
// committed directly in source alongside the open-source validation
// algorithm — anyone who read the repo had everything needed to mint a
// passing license, and the key could never rotate without a code change
// and a release. See docs/improvement_spec.md item #4.
const LicenseSecretEnvVar = "SECOPS_LICENSE_SECRET"

// NewLicenseValidator builds a validator from an explicit key. Prefer
// NewLicenseValidatorFromEnv in production so the key is never captured in
// source control, command-line arguments, or process listings.
func NewLicenseValidator(secretKey []byte) (*LicenseValidator, error) {
	if len(secretKey) < 32 {
		return nil, fmt.Errorf("license secret key must be at least 32 bytes, got %d", len(secretKey))
	}
	return &LicenseValidator{secretKey: secretKey}, nil
}

// NewLicenseValidatorFromEnv reads the HMAC signing key from
// SECOPS_LICENSE_SECRET. It is an error for this variable to be unset so a
// misconfigured deployment fails closed instead of silently running
// without license enforcement.
func NewLicenseValidatorFromEnv() (*LicenseValidator, error) {
	raw := os.Getenv(LicenseSecretEnvVar)
	if raw == "" {
		return nil, fmt.Errorf("%s is not set", LicenseSecretEnvVar)
	}
	return NewLicenseValidator([]byte(raw))
}

func (lv *LicenseValidator) VerifyMachineLicense(lic *CommercialLicense) (bool, error) {
	if lic == nil || strings.TrimSpace(lic.LicenseKey) == "" {
		return false, fmt.Errorf("license key is empty: %w", kerncode.LicensingTokenMissing)
	}

	// 1. Enforce temporal boundary validity window checks
	adjustedExpiry := lic.ExpirationTime.Add(time.Duration(lic.GracePeriodMs) * time.Millisecond)
	if time.Now().After(adjustedExpiry) {
		return false, fmt.Errorf("license expired at %s: %w", adjustedExpiry, kerncode.LicensingTokenExpired)
	}

	// 2. Verify an HMAC-SHA256 signature over the license fields, using a
	// secret key that is never embedded in source. hmac.Equal is used
	// instead of a plain byte-slice/string comparison to avoid leaking
	// timing information about how many leading bytes matched.
	mac := hmac.New(sha256.New, lv.secretKey)
	mac.Write([]byte(fmt.Sprintf("%s:%s", lic.OEMVendorID, lic.ExpirationTime.Format(time.RFC3339))))
	expectedMAC := mac.Sum(nil)

	providedMAC, err := hex.DecodeString(strings.TrimSpace(lic.LicenseKey))
	if err != nil || !hmac.Equal(providedMAC, expectedMAC) {
		return false, fmt.Errorf("provided license key does not match the expected signature: %w", kerncode.LicensingSignatureMismatch)
	}

	return true, nil
}
