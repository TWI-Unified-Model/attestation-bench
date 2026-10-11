package cai

import "testing"

// The Evidence binds no RRP identifier unless WithRelyingPartyBinding asks for the held one (the variant measured
// against it, docs/rrp-identifier.md); the identifier is left out of the binding alone.
func TestBoundRelyingParty(t *testing.T) {
	const held = "https://ca1.tacra.example"
	c := &Client{}
	if got := c.boundRelyingParty(held); got != "" {
		t.Errorf("bound %q by default, want none (the decision of 6 October 2026)", got)
	}
	WithRelyingPartyBinding()(c)
	if got := c.boundRelyingParty(held); got != held {
		t.Errorf("bound %q with the binding asked for, want the held identifier", got)
	}
}
