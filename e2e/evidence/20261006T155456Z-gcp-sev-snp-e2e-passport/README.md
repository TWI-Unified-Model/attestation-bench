# TACRA over EST end to end on GCP SEV-SNP, the rebuilt bench (06.10.2026, 15:54–15:57Z)

**Code:**
- branch `bench/rebuild` (see `code-revs.txt`): the TWI SIG's main `0d858d0` with our work ported onto it;
- globalsign-est `tacra/deployed-rrp`;
- Veraison from `veraison-services-der`.

The bench binaries were rebuilt from this tree at 15:53Z (`binaries.sha256`). RATS model: Passport (`rats-model.txt`),
the decision of the TWI SIG meeting of 06.10.

**Platform:**
- `tacra-e2e-2610061554`: n2d-standard-2, AMD Milan, SEV-SNP, us-central1-c, kernel `7.0.0-1011-gcp` (`kernel.txt`);
- configfs-tsm `report` present.

**Run:**
- In the guest: the SIG's CAI with the SEV-SNP plug-in (`e2e-attester`) and the CAS Client (`caapi-est`).
- On the Mac: the bench, reached through an SSH reverse tunnel.
- Ten Targets: five Freshness Kinds (`nonce`, `epoch`, `lepoch`, `time`, `none`), each once as Enrollment (x509 from
  the CA gateway over step-ca) and once as Retrieval (api-key from the Vault gateway).

**Result: 10 of 10.** Each credential was acquired on the first attempt, in 490–713 ms, and admitted by the
relying party: 200 from the mTLS service for x509, 200 for the API key (`results.json`, `e2e-attester-stdout.txt`).

**The binding, checked on hardware by three separate code paths:**
1. The guest computed REPORT_DATA with the platform package of the group's main, called through the CAI. That path
   includes the Target added by our ported commit and the argument order swapped in `e00ad10`.
2. In Passport, the EST server opened each Veraison session with its own binding value, computed by its own code
   (globalsign-est `internal/tacra/binding.go:18`, `backend.go:420`), not by the platform package.
3. The CA and Vault gateways recomputed the binding with their own RRP identifier
   (`rrp/internal/gateway/gateway.go:388`).

Veraison answered `affirming` for all ten SEVSNP sessions (`bench-logs/veraison-vts.log`, `eat_nonce` equal to the
session nonce), and both gateways issued. So paths 1, 2 and 3 agree on real hardware: the argument swap is right.

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again independently afterwards: the project had 0 instances
and 0 disks.

**Not proved here:**
- Attacks (substitution, redirection) were not part of this run. They follow on the rebuilt bench.
- `attest-initiate` still carries `credential_type` (TACRA master text; #19 pending).
