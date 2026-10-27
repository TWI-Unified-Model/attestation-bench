module github.com/TWI-Unified-Model/tacra/e2e

go 1.27.3

require (
	github.com/TWI-Unified-Model/tacra/bundle v0.0.0
	github.com/TWI-Unified-Model/tacra/cai v0.0.0-00010101000000-000000000000
	github.com/TWI-Unified-Model/tacra/gen/go v0.0.0
	github.com/TWI-Unified-Model/tacra/platform v0.0.0-00010101000000-000000000000
	github.com/globalsign/est v0.0.0
	github.com/jackc/pgx/v5 v5.11.0
	google.golang.org/grpc v1.83.2
)

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-chi/chi/v5 v5.3.2 // indirect
	github.com/google/go-configfs-tsm v0.3.2 // indirect
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/go-tpm v0.9.6 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/smallstep/scep v0.0.0-20250318231241-a25cabb69492 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/veraison/eat v0.0.0-20251105185612-2c0e43e22ea9 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/veraison/swid v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/TWI-Unified-Model/tacra/bundle => ../bundle
	github.com/TWI-Unified-Model/tacra/cai => ../cai
	github.com/TWI-Unified-Model/tacra/gen/go => ../gen/go
	github.com/TWI-Unified-Model/tacra/platform => ../platform
	github.com/globalsign/est => ../third_party/globalsign-est/src
)
