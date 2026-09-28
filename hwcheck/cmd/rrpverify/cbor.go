package main

import "github.com/fxamacker/cbor/v2"

func cborUnmarshal(b []byte, v any) error { return cbor.Unmarshal(b, v) }

func cborMarshal(v any) ([]byte, error) { return cbor.Marshal(v) }
