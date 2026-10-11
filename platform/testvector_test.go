package platform

// Test vector of draft-novak-lamps-tacra-est ("Test Vector for the Binding Input") of 30 September 2026, the layout with
// the RRP identifier (BindingValueRRP; the runs before 12 October), in the order of the TACRA section
// "Binding Credential Keys to Evidence": the enrollment of SEV-SNP run 20260930T172002Z, where
// SHA-512(binding_input) equals REPORT_DATA of the hardware report (github.com/nikolaichuk7/tacra-est, commit
// 5661be5). tvBindingInputLen is the length of binding_input the draft gives.
const (
	tvHandleHex       = "f8170e6438729e1e3ded60c7c8b220716b7138f9a7e6250c569f1548790ee25f"
	tvRRPID           = "https://ca1.tacra.example"
	tvTarget          = "https://db.tacra.example"
	tvSubjectHex      = "3081dc3081830201003021311f301d06035504030c16776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d0301070342000458f74deb3089c1ba23a2a630a94812f503377fa33d252cd5b2a287fefa40bca353ff2671caa8565de5cc5d221d2a61e5610f9748224dd4a210c82bdfa329d7c2a000300a06082a8648ce3d0403020348003045022100a214dc7a98c6dd8c702a38cc2acabbf0fc7391491a546720f69bf29fdbe7056202205708ed7cf3fc25d8f2501639a589a69be2aa8468f97ff4008d3ea124147a0347"
	tvDigestHex       = "c5d8f3e4a93130e864df61ef1bf940223d8d891fa668d21aceffb34f20473065c3cf80a64ccd0c8c5a60717a5d25cb8b2131bf2e51be88f7beadba6bb181d4ca"
	tvBindingInputLen = 320
)

// The hardware vector of the binding of 11 October 2026, three fields (the freshness element, the Target, the subject):
// the present-nonce Enrollment of the attack run 20261011T151929Z-gcp-sev-snp (hwcheck/evidence), the first run of that
// layout, whose REPORT_DATA equals SHA-512(binding_input); the four-field layout with an empty identifier gives another value.
const (
	tv3HandleHex     = "a8dd37281155a104a3565cc7ce2057d508dd978c00b2f1fa1e2591da88d508b3"
	tv3Target        = "https://db.tacra.example"
	tv3SubjectHex    = "3081dc3081830201003021311f301d06035504031316776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200043f7db1f117615222a44ba5aa38e46f081aba244ac212b9a4fdad6b32c1d652efc8ee87a58a5c527c8fb3f99fb73e9672ee16295162a644d1d8f347514a3cc334a000300a06082a8648ce3d0403020348003045022100faac6730de9d236b9ceda664aaa5c8141ca611994b2be69e7d9faf1a1643aed2022023ddf3e5bd48fcb1e9ced32a21b73a81385f4763a752dfc3d735b7d313998968"
	tv3ReportDataHex = "79e35ac63f0dd8ec89d31afcab8ede5d993de21003af1b16d90f43c5a8f788f99cd8013e75f615ede1acb4fcee27d732063570e97b8a22c2da8d5eec8240c4fd"
)
