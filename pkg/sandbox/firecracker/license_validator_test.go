package firecracker

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVerifyMachineLicense_Valid(t *testing.T) {
	salt := "enterprise_secret_salt_2026"
	vendor := "crewai-oem-adapter"
	expiry := time.Now().Add(24 * time.Hour)

	// Generate the expected production signature hash
	rawPayload := fmt.Sprintf("%s:%s:%s", vendor, expiry.Format(time.RFC3339), salt)
	expectedHash := sha256.Sum256([]byte(rawPayload))
	validKeySignature := fmt.Sprintf("%x", expectedHash)

	validator := NewLicenseValidator(salt)
	lic := &CommercialLicense{
		OEMVendorID:    vendor,
		LicenseKey:     validKeySignature,
		ExpirationTime: expiry,
		GracePeriodMs:  0,
	}

	passed, err := validator.VerifyMachineLicense(lic)
	if err != nil {
		t.Fatalf("Expected valid license to pass, got error: %v", err)
	}
	if !passed {
		t.Fatal("Expected valid license verification result to be true, got false")
	}
}

func TestVerifyMachineLicense_Expired(t *testing.T) {
	salt := "enterprise_secret_salt_2026"
	vendor := "langgraph-oem-adapter"
	expiry := time.Now().Add(-1 * time.Hour) // Core window explicitly set in the past

	validator := NewLicenseValidator(salt)
	lic := &CommercialLicense{
		OEMVendorID:    vendor,
		LicenseKey:     "mock_signature_hash",
		ExpirationTime: expiry,
		GracePeriodMs:  0,
	}

	passed, err := validator.VerifyMachineLicense(lic)
	if err == nil {
		t.Fatal("Expected validation to return temporal fault error, got nil")
	}
	if passed {
		t.Fatal("Expected expired token state check to return false, got true")
	}
}

func TestVerifyMachineLicense_InvalidSignature(t *testing.T) {
	salt := "enterprise_secret_salt_2026"
	validator := NewLicenseValidator(salt)
	
	lic := &CommercialLicense{
		OEMVendorID:    "autogen-oem-adapter",
		LicenseKey:     "invalid_fraudulent_signature_bytes",
		ExpirationTime: time.Now().Add(10 * time.Hour),
		GracePeriodMs:  0,
	}

	passed, err := validator.VerifyMachineLicense(lic)
	if err == nil || !strings.Contains(err.Error(), "0x00_LICENSING_SIGNATURE_MISMATCH") {
		t.Fatalf("Expected signature mismatch error, got: %v", err)
	}
	if passed {
		t.Fatal("Expected invalid signature result to evaluate to false, got true")
	}
}
