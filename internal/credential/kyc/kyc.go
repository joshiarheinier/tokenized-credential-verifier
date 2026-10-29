// Package kyc defines the KYCStatus credential type: the facts an identity
// verification issuer attests to. It is one credential type among others the
// system can carry; the credential package itself knows nothing about it.
//
// The claims are deliberately coarse: no name, birthdate, address or document
// data. The schema rejects any other claim, so an issuer cannot attach extra
// personal data to a KYC credential.
package kyc

import (
	"fmt"
	"regexp"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/credential"
)

const (
	// Type is the credential_type value of a KYC status credential.
	Type = "KYCStatus"

	ClaimVerified = "kyc_verified"
	ClaimOver18   = "over_18"
	ClaimCountry  = "country"
)

var countryRE = regexp.MustCompile(`^[A-Z]{2}$`)

// Schema describes the KYCStatus claims.
var Schema = credential.Schema{
	Type: Type,
	Fields: []credential.Field{
		{Name: ClaimVerified, Kind: credential.Bool, Required: true},
		{Name: ClaimOver18, Kind: credential.Bool, Required: true},
		{Name: ClaimCountry, Kind: credential.String, Required: true, Check: checkCountry},
	},
}

func checkCountry(v any) error {
	if s, _ := v.(string); !countryRE.MatchString(s) {
		return fmt.Errorf("must be an ISO 3166-1 alpha-2 code such as ID")
	}
	return nil
}
