module github.com/TWI-Unified-Model/tacra/rrp

go 1.27.3

require (
	fortio.org/safecast v1.0.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-configfs-tsm v0.3.2 // indirect
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/veraison/eat v0.0.0-20251105185612-2c0e43e22ea9 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/veraison/swid v1.1.1-0.20251003121634-fd1f7f1e1897 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/TWI-Unified-Model/tacra/platform => ../platform

require (
	github.com/TWI-Unified-Model/tacra/bundle v0.0.0
	github.com/TWI-Unified-Model/tacra/platform v0.0.0-00010101000000-000000000000
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/google/gce-tcb-verifier v0.3.1
	github.com/google/go-tdx-guest v0.3.1
	github.com/veraison/corim v1.1.3-0.20260430132037-b8653a7359da
	google.golang.org/protobuf v1.33.0
)

replace github.com/TWI-Unified-Model/tacra/bundle => ../bundle
