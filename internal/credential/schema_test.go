package credential

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestSchemaValidate(t *testing.T) {
	ok := map[string]any{"tier": "gold", "vip": true}
	cases := map[string]struct {
		claims map[string]any
		valid  bool
	}{
		"required claims only":     {ok, true},
		"optional number (float)":  {map[string]any{"tier": "gold", "vip": true, "seats": 4.0}, true},
		"optional number (int)":    {map[string]any{"tier": "gold", "vip": true, "seats": 4}, true},
		"optional number (json)":   {map[string]any{"tier": "gold", "vip": true, "seats": json.Number("4")}, true},
		"missing required":         {map[string]any{"tier": "gold"}, false},
		"nil claims":               {nil, false},
		"wrong kind (string)":      {map[string]any{"tier": 7, "vip": true}, false},
		"wrong kind (bool)":        {map[string]any{"tier": "gold", "vip": "yes"}, false},
		"wrong kind (number)":      {map[string]any{"tier": "gold", "vip": true, "seats": "4"}, false},
		"unknown claim is refused": {map[string]any{"tier": "gold", "vip": true, "email": "a@b.c"}, false},
	}
	for name, tc := range cases {
		err := testSchemas.Validate(testType, tc.claims)
		if tc.valid && err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if !tc.valid && !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("%s: err = %v, want ErrInvalidClaims", name, err)
		}
	}
}

func TestInvalidClaimsAreMalformed(t *testing.T) {
	if !errors.Is(ErrInvalidClaims, ErrMalformed) {
		t.Fatal("ErrInvalidClaims must be a kind of ErrMalformed so callers that only know ErrMalformed still reject it")
	}
}

func TestFieldCheckRuns(t *testing.T) {
	set := mustSchemas(Schema{Type: "T", Fields: []Field{{
		Name: "code", Kind: String, Required: true,
		Check: func(v any) error {
			if v.(string) != "ok" {
				return errors.New("must be ok")
			}
			return nil
		},
	}}})
	if err := set.Validate("T", map[string]any{"code": "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := set.Validate("T", map[string]any{"code": "no"}); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("err = %v, want ErrInvalidClaims", err)
	}
}

func TestSchemasUnknownTypeAndNilSet(t *testing.T) {
	if err := testSchemas.Validate("Nope", nil); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("unknown type: err = %v, want ErrUnsupportedType", err)
	}
	var none *Schemas
	if err := none.Validate(testType, map[string]any{"tier": "gold", "vip": true}); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("nil set: err = %v, want ErrUnsupportedType (a nil set accepts nothing)", err)
	}
}

func TestNewSchemasRejectsBadDefinitions(t *testing.T) {
	f := Field{Name: "a", Kind: Bool}
	cases := map[string][]Schema{
		"empty type":      {{Type: "", Fields: []Field{f}}},
		"duplicate type":  {{Type: "T"}, {Type: "T"}},
		"duplicate field": {{Type: "T", Fields: []Field{f, f}}},
		"empty field":     {{Type: "T", Fields: []Field{{Name: "", Kind: Bool}}}},
		"missing kind":    {{Type: "T", Fields: []Field{{Name: "a"}}}},
	}
	for name, s := range cases {
		if _, err := NewSchemas(s...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	set, err := NewSchemas(Schema{Type: "B"}, Schema{Type: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Types(); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("Types() = %v, want sorted [A B]", got)
	}
}

func TestServiceRejectsApprovalsThatDoNotMatchTheirType(t *testing.T) {
	reg := &fakeBlockchainClient{}
	for name, a := range map[string]Approval{
		"unknown type":     {Subject: "u", CredentialType: "Nope", Claims: map[string]any{"tier": "gold", "vip": true}},
		"claims mismatch":  {Subject: "u", CredentialType: testType, Claims: map[string]any{"tier": "gold"}},
		"unexpected claim": {Subject: "u", CredentialType: testType, Claims: map[string]any{"tier": "gold", "vip": true, "ssn": "x"}},
	} {
		svc, _ := NewService(newSigner(t), &fakeApprovals{approval: a}, testSchemas, 3600e9, nil, WithBlockchainClient(reg))
		issued, err := svc.IssueFromApproval(t.Context(), "id")
		if err == nil || issued.Token != "" {
			t.Errorf("%s: issued=%+v err=%v, want a refusal", name, issued, err)
		}
	}
	if len(reg.calls) != 0 {
		t.Fatal("an invalid approval must not be registered on chain")
	}
}
