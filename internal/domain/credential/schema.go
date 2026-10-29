package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// FieldKind is the JSON type of a claim value.
type FieldKind int

const (
	Bool FieldKind = iota + 1
	String
	Number
)

func (k FieldKind) String() string {
	switch k {
	case Bool:
		return "boolean"
	case String:
		return "string"
	case Number:
		return "number"
	}
	return "unknown"
}

// Field describes one claim of a credential type.
type Field struct {
	Name     string
	Kind     FieldKind
	Required bool
	// Check optionally validates the value once its kind has been verified.
	Check func(value any) error
}

// Schema defines a credential type: the claims it carries and their kinds.
// Claims are validated strictly: fields not listed are rejected, so an issuer
// cannot attach extra, unreviewed (possibly personal) data to a credential.
type Schema struct {
	// Type is the value of the credential_type claim.
	Type   string
	Fields []Field
}

// ErrInvalidClaims means a claim set does not match its credential type's
// schema. It is a kind of ErrMalformed.
var ErrInvalidClaims = fmt.Errorf("%w: invalid claims", ErrMalformed)

// Validate checks a claim set against the schema.
func (s Schema) Validate(claims map[string]any) error {
	known := make(map[string]Field, len(s.Fields))
	for _, f := range s.Fields {
		known[f.Name] = f
	}
	for name := range claims {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("%w: unknown claim %q", ErrInvalidClaims, name)
		}
	}
	for _, f := range s.Fields {
		v, present := claims[f.Name]
		if !present {
			if f.Required {
				return fmt.Errorf("%w: missing claim %q", ErrInvalidClaims, f.Name)
			}
			continue
		}
		if !kindMatches(f.Kind, v) {
			return fmt.Errorf("%w: claim %q must be a %s", ErrInvalidClaims, f.Name, f.Kind)
		}
		if f.Check != nil {
			if err := f.Check(v); err != nil {
				return fmt.Errorf("%w: claim %q: %v", ErrInvalidClaims, f.Name, err)
			}
		}
	}
	return nil
}

func kindMatches(k FieldKind, v any) bool {
	switch k {
	case Bool:
		_, ok := v.(bool)
		return ok
	case String:
		_, ok := v.(string)
		return ok
	case Number:
		switch v.(type) {
		case float64, float32, int, int32, int64, json.Number:
			return true
		}
	}
	return false
}

// Schemas is the set of credential types a deployment understands. It is
// immutable once built and safe for concurrent use.
type Schemas struct {
	byType map[string]Schema
}

// NewSchemas builds a Schemas set, rejecting empty or duplicate type names and
// duplicate or empty field names.
func NewSchemas(schemas ...Schema) (*Schemas, error) {
	s := &Schemas{byType: make(map[string]Schema, len(schemas))}
	for _, sc := range schemas {
		if sc.Type == "" {
			return nil, errors.New("credential: schema type is required")
		}
		if _, dup := s.byType[sc.Type]; dup {
			return nil, fmt.Errorf("credential: duplicate schema for type %q", sc.Type)
		}
		seen := make(map[string]bool, len(sc.Fields))
		for _, f := range sc.Fields {
			if f.Name == "" || f.Kind < Bool || f.Kind > Number {
				return nil, fmt.Errorf("credential: type %q has an invalid field %q", sc.Type, f.Name)
			}
			if seen[f.Name] {
				return nil, fmt.Errorf("credential: type %q declares claim %q twice", sc.Type, f.Name)
			}
			seen[f.Name] = true
		}
		s.byType[sc.Type] = sc
	}
	return s, nil
}

// Validate checks claims against the schema of credentialType. It returns
// ErrUnsupportedType if the type is not in the set.
func (s *Schemas) Validate(credentialType string, claims map[string]any) error {
	if s == nil {
		return ErrUnsupportedType // a nil set accepts nothing
	}
	sc, ok := s.byType[credentialType]
	if !ok {
		return ErrUnsupportedType
	}
	return sc.Validate(claims)
}

// Types returns the supported credential types, sorted.
func (s *Schemas) Types() []string {
	out := make([]string, 0, len(s.byType))
	for t := range s.byType {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
