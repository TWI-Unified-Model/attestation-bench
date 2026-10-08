package cai

import "testing"

// The #20 variant: WithoutRelyingPartyBinding leaves the identifier out of the Evidence's binding and nowhere else.
func TestBoundRelyingParty(t *testing.T) {
	const held = "https://ca1.tacra.example"
	c := &Client{}
	if got := c.boundRelyingParty(held); got != held {
		t.Errorf("bound %q, want the held identifier", got)
	}
	WithoutRelyingPartyBinding()(c)
	if got := c.boundRelyingParty(held); got != "" {
		t.Errorf("bound %q with the binding omitted, want none", got)
	}
}
