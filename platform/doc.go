// Package platform is the TACRA Platform Plug-In used by the Credential
// Acquisition Interface (CAI).
//
// CAI calls this package to generate Credential Encryption Keys (CEK),
// Credential Signing Keys (CSK), and Remote Attestation Evidence. The
// back-ends are AMD SEV-SNP (sevsnp.go) and Intel TDX (tdx.go), through the
// Linux configfs-tsm interface: the Evidence is the hardware's report, whose
// report data is the TACRA binding value (binding.go), with the host's
// certificates.
package platform
