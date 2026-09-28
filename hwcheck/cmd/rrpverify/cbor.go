package main

import "github.com/fxamacker/cbor/v2"

// deterministic encoding (RFC 8949, Section 4.2.1), so that a rewritten token is the same bytes on every run
var encMode, _ = cbor.CoreDetEncOptions().EncMode()

func cborUnmarshal(b []byte, v any) error { return cbor.Unmarshal(b, v) }

func cborMarshal(v any) ([]byte, error) { return encMode.Marshal(v) }
