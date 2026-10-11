package platform

import (
	"crypto/sha512"
	"encoding/binary"
)

// BindingLayout names the binding of 11 October 2026 in a run's record (hwcheck cases.json, binding_layout): the
// freshness element, the Target and the subject, no identifier of any party. Records without it are the runs of
// 6 to 11 October, whose binding carried a fourth field, the RRP identifier, bound or empty (BindingValueRRP).
const BindingLayout = "freshness-target-subject"

// BindingInput is the octet string of the TACRA section "Binding Credential Keys to Evidence" as the group decided
// on 6 and 11 October 2026 (TheBankster/rats-tacra#20): each value preceded by its length as a 32-bit big-endian
// integer, and no Relying Party or server identifier.
//
//	binding_input = len32(handle) || handle || len32(target) || target || len32(subject) || subject
//
// handle is the freshness element (the Freshness Handle, the epoch marker or the 8-octet timestamp; empty only for
// absent-none), target the Target, and subject the DER CSR (Enrollment) or the DER SubjectPublicKeyInfo of CEKpub
// (Retrieval).
func BindingInput(handle []byte, target string, subject []byte) []byte {
	var out []byte
	for _, v := range [][]byte{handle, []byte(target), subject} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}

// BindingValue is SHA-512 of BindingInput: the 64 octets a hardware back-end
// writes into its guest-chosen report field (REPORT_DATA on AMD SEV-SNP).
func BindingValue(handle []byte, target string, subject []byte) [sha512.Size]byte {
	return sha512.Sum512(BindingInput(handle, target, subject))
}

// BindingInputRRP is the layout of before 12 October 2026, with the RRP identifier as a fourth field between the
// Target and the subject (bound, or empty in the runs of 8 to 11 October). No Evidence is made with it any more; it
// is kept so that the committed runs of 6 to 11 October are appraised as they ran (hwcheck rrpverify, by the run's
// own record).
func BindingInputRRP(handle []byte, target, rrpID string, subject []byte) []byte {
	var out []byte
	for _, v := range [][]byte{handle, []byte(target), []byte(rrpID), subject} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}

// BindingValueRRP is SHA-512 of BindingInputRRP.
func BindingValueRRP(handle []byte, target, rrpID string, subject []byte) [sha512.Size]byte {
	return sha512.Sum512(BindingInputRRP(handle, target, rrpID, subject))
}

// TimestampElementSize is the length in octets of the absent-timestamp freshness
// element.
const TimestampElementSize = 8

// TimestampElement is the absent-timestamp freshness element: seconds since
// 1970-01-01T00:00:00Z as an 8-octet big-endian unsigned integer.
func TimestampElement(unixSeconds int64) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(unixSeconds))
}
