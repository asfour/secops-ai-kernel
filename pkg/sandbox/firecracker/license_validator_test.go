package firecracker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testSecretKey = "test-only-secret-key-at-least-32-bytes-long"

func signLicense(t *testing.T, secretKey []byte, vendor string, expiry time.Time) string {
	t.Helper()
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(fmt.Sprintf("%s:%s", vendor, expiry.Format(time.RFC3339))))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyMachineLicense_Valid(t *testing.T) {
	vendor := "crewai-oem-adapter"
	expiry := time.Now().Add(24 * time.Hour)
	validKeySignature := signLicense(t, []byte(testSecretKey), vendor, expiry)

	validator, err := NewLicenseValidator([]byte(testSecretKey))
	if err != nil {
		t.Fatalf("unexpected error constructing validator: %v", err)
	}

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
	vendor := "langgraph-oem-adapter"
	expiry := time.Now().Add(-1 * time.Hour) // Core window explicitly set in the past

	validator, err := NewLicenseValidator([]byte(testSecretKey))
	if err != nil {
		t.Fatalf("unexpected error constructing validator: %v", err)
	}

	lic := &CommercialLicense{
		OEMVendorID:    vendor,
		LicenseKey:     "deadbeef",
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
	validator, err := NewLicenseValidator([]byte(testSecretKey))
	if err != nil {
		t.Fatalf("unexpected error constructing validator: %v", err)
	}

	lic := &CommercialLicense{
		OEMVendorID:    "autogen-oem-adapter",
		LicenseKey:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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

func TestNewLicenseValidator_RejectsShortKey(t *testing.T) {
	if _, err := NewLicenseValidator([]byte("too-short")); err == nil {
		t.Fatal("expected a short secret key to be rejected")
	}
}

func TestNewLicenseValidatorFromEnv(t *testing.T) {
	t.Setenv(LicenseSecretEnvVar, testSecretKey)
	if _, err := NewLicenseValidatorFromEnv(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Setenv(LicenseSecretEnvVar, "")
	if _, err := NewLicenseValidatorFromEnv(); err == nil {
		t.Fatal("expected an unset secret env var to be rejected")
	}
}
