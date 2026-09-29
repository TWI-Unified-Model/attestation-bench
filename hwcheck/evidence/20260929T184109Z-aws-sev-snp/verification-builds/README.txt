Modfiles for the rrpverify builds behind rrpverify-veraison-{fork,fixed}-at-veraison-pin.*: hwcheck/go.mod and
hwcheck/go.patched.mod of the tested tree plus one replace that holds go-sev-guest at the version
veraison-services pins (v0.14.2-0.20251119154202-af1c107a648f). hwrun, the Attester, was built without it (v0.15.0,
as in PR 1). Build: cd hwcheck && GOWORK=off go build -modfile=<file> ./cmd/rrpverify, after copying the file into
hwcheck/ (its replace paths are relative to it). Why: evidence/20260929-go-sev-guest-v0.15.0-vlek/README.md.
