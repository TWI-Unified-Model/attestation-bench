package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/TWI-Unified-Model/tacra/cai"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	caiv1 "github.com/TWI-Unified-Model/tacra/gen/go/cai/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	listen := envOr("CAI_LISTEN", ":50051")
	caapiAddr := envOr("CAAPI_ADDR", "127.0.0.1:9090")

	plugin, err := platform.NewSimulated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "platform plug-in: %v\n", err)
		os.Exit(1)
	}

	// The Relying Party identifier the CAI binds, per Target and mode (TACRA Section 4.5): whitespace-separated
	// entries TARGET|MODE|RRP_ID, MODE being enroll or retrieve. Without one, the CAI acquires nothing.
	rps := map[string]map[string]string{}
	for _, entry := range strings.Fields(os.Getenv("CAI_RELYING_PARTIES")) {
		f := strings.Split(entry, "|")
		if len(f) != 3 {
			fmt.Fprintf(os.Stderr, "CAI_RELYING_PARTIES: %q is not TARGET|MODE|RRP_ID\n", entry)
			os.Exit(1)
		}
		if rps[f[0]] == nil {
			rps[f[0]] = map[string]string{}
		}
		rps[f[0]][f[1]] = f[2]
	}
	opts, err := cai.RelyingParties(rps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAI_RELYING_PARTIES: %v\n", err)
		os.Exit(1)
	}

	conn, err := grpc.NewClient(caapiAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAAPI dial %s: %v\n", caapiAddr, err)
		os.Exit(1)
	}
	defer conn.Close()
	inner, err := cai.New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn), opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAI: %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", listen, err)
		os.Exit(1)
	}

	s := grpc.NewServer()
	caiv1.RegisterCredentialAcquisitionInterfaceServer(s, cai.NewGRPC(inner))
	fmt.Printf("CAI sidecar on %s (CAAPI %s; Relying Party identifiers held for %d Targets)\n", listen, caapiAddr, len(rps))
	if err := s.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "CAI sidecar failed: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
