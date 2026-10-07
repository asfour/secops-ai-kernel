package firecracker

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

type CommercialLicense struct {
	OEMVendorID   string
	LicenseKey    string
	ExpirationTime time.Time
	GracePeriodMs int64
}

type LicenseValidator struct {
	SecretSalt string
}

func NewLicenseValidator(salt string) *LicenseValidator {
	return &LicenseValidator{
		SecretSalt: salt,
	}
}

func (lv *LicenseValidator) VerifyMachineLicense(lic *CommercialLicense) (bool, error) {
	if lic == nil || strings.TrimSpace(lic.LicenseKey) == "" {
		return false, fmt.Errorf("0x00_LICENSING_TOKEN_MISSING")
	}

	// 1. Enforce temporal boundary validity window checks
	adjustedExpiry := lic.ExpirationTime.Add(time.Duration(lic.GracePeriodMs) * time.Millisecond)
	if time.Now().After(adjustedExpiry) {
		return false, fmt.Errorf("0x00_LICENSING_TOKEN_EXPIRED")
	}

	// 2. Perform out-of-band SHA-256 cryptographic verification matching expected signature hashes
	rawPayload := fmt.Sprintf("%s:%s:%s", lic.OEMVendorID, lic.ExpirationTime.Format(time.RFC3339), lv.SecretSalt)
	expectedHash := sha256.Sum256([]byte(rawPayload))
	generatedKeySignature := fmt.Sprintf("%x", expectedHash)

	if lic.LicenseKey != generatedKeySignature {
		return false, fmt.Errorf("0x00_LICENSING_SIGNATURE_MISMATCH")
	}

	return true, nil
}
