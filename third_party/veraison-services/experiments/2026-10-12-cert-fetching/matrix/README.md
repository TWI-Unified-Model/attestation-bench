# The matrix: five variants of the scheme × two go-sev-guest versions × real reports

12 October 2026, run 20:5xZ on the Mac. One test (`matrix_test.go`) is dropped into five checkouts of
veraison/services and run twice each, on the pinned go-sev-guest (v0.14.2-0.20251119154202-af1c107a648f)
and on v0.15.0; `matrix.sh` does the loop, `render.py` draws `matrix.md` from `matrix.txt` (70 rows).

| variant | code |
|---|---|
| main | b1cd67e (the base of PRs #488 and #490) |
| main + flag | b1cd67e with `DisableCertFetching: false` (the proposal on #490) |
| #488 | 283df9a (DER certificates in the host table) |
| #488 + flag | 283df9a with `DisableCertFetching: false` |
| #488 + #490 | d73ae83 (the chain verified up to AMD's roots held by the scheme) |

Inputs: upstream's own Genoa/PEM sample (their test data), the GCP Milan VCEK report (7 Oct 2026) with the
host's table and cut down to the VCEK alone, the AWS Milan VLEK report (6 Oct 2026) with the host's table
(VLEK alone) and as the guest appended ASVK+ARK, and the two leaf-alone reports through one process in a row
(go-sev-guest's product-chain cache). Each cell: `GetTrustAnchorIDs` then `ValidateEvidenceIntegrity` with
AMD's ARK of the product line as the provisioned trust anchor; the number of requests to `kdsintf.amd.com`
counted at `http.DefaultTransport`.

Result (`matrix.md`): only upstream's own sample passes on main; the flag changes nothing on any variant and
never produces a KDS request, since the scheme refuses the table before go-sev-guest runs; #488 admits the GCP
table and, on the pinned go-sev-guest only, the AWS table with the chain appended by the guest; #488 + #490
passes every input on both versions with no KDS request. The fetching half on its own, after the scheme is
rewritten, is measured in `../exp_fetching_test.go` (E2, E3).

Reproduce: five detached worktrees of the commits above under `mx/`, the two fixtures copied into each
`scheme/sevsnp/test/evidence/`, `sed` the flag in `flag` and `derflag`, then `./matrix.sh` and `./render.py matrix.txt`.
