// Package kerncode defines the "0x00_SCREAMING_SNAKE_CASE" verdict/error
// code taxonomy used across license validation, consensus, and intent
// compilation.
//
// Previously these codes were free-form string literals passed straight to
// fmt.Errorf at each call site (e.g. fmt.Errorf("0x00_LICENSING_TOKEN_EXPIRED")),
// checked elsewhere with strings.Contains(err.Error(), "..."). A typo in
// either the literal or the check would silently pass review and silently
// test the wrong failure mode. See IMPROVEMENT_SPEC.md item #12.
//
// A Code implements error, so existing fmt.Errorf("...: %w", kerncode.X)
// call sites still produce a message containing the code string (so
// strings.Contains checks keep working), while new call sites should
// prefer errors.Is(err, kerncode.X).
package kerncode

type Code struct {
	name string
}

func (c Code) Error() string { return c.name }

var (
	LicensingTokenMissing      = Code{"0x00_LICENSING_TOKEN_MISSING"}
	LicensingTokenExpired      = Code{"0x00_LICENSING_TOKEN_EXPIRED"}
	LicensingSignatureMismatch = Code{"0x00_LICENSING_SIGNATURE_MISMATCH"}

	ConsensusTimeoutDeadlock = Code{"0x00_CONSENSUS_TIMEOUT_DEADLOCK"}

	IntentInvariantViolation = Code{"0x00_INTENT_INVARIANT_VIOLATION"}
	IntentGraphMalformed     = Code{"0x00_INTENT_GRAPH_MALFORMED"}

	ExecutionWindowExceedsConfiguredCeiling = Code{"0x00_EXECUTION_WINDOW_EXCEEDS_CONFIGURED_CEILING"}
)
