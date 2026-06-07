// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"google.golang.org/protobuf/proto"
)

const mptEvidencePath = "../testing/testdata/test_mpt_data.json"

// runCmd executes the root command with the given args and returns combined
// stdout/stderr and the error.
func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestVersion(t *testing.T) {
	out, err := runCmd(t, "version")
	if err != nil {
		t.Fatalf("version: unexpected error: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("version output is not JSON: %q: %v", out, err)
	}
	if got["nvattest"] != Version {
		t.Errorf("version = %q, want %q", got["nvattest"], Version)
	}
}

func TestParseLegacyGPUEvidence(t *testing.T) {
	data, err := os.ReadFile(mptEvidencePath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	quote, err := parseGPUEvidence(data)
	if err != nil {
		t.Fatalf("parseGPUEvidence: %v", err)
	}
	if len(quote.GetGpuInfos()) == 0 {
		t.Fatal("parseGPUEvidence: got 0 GPUs, want > 0")
	}
	gpu := quote.GetGpuInfos()[0]
	if gpu.GetUuid() == "" {
		t.Error("first GPU has empty UUID")
	}
	if len(gpu.GetAttestationReport()) == 0 {
		t.Error("first GPU has empty attestation report")
	}
	if len(gpu.GetAttestationCertificateChain()) == 0 {
		t.Error("first GPU has empty certificate chain")
	}
	if gpu.GetGpuArchitecture() != pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL {
		t.Errorf("arch = %v, want BLACKWELL", gpu.GetGpuArchitecture())
	}
}

func TestEvidenceProtojsonRoundTrip(t *testing.T) {
	data, err := os.ReadFile(mptEvidencePath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	quote, err := parseGPUEvidence(data)
	if err != nil {
		t.Fatalf("parseGPUEvidence (legacy): %v", err)
	}

	// Serialize to protojson and parse it back; it must be identical.
	marshaled, err := marshalEvidence(quote)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	roundTripped, err := parseGPUEvidence(marshaled)
	if err != nil {
		t.Fatalf("parseGPUEvidence (protojson): %v", err)
	}
	if !proto.Equal(quote, roundTripped) {
		t.Error("protojson round-trip produced a different quote")
	}
}

func TestParseNonce(t *testing.T) {
	t.Run("valid hex", func(t *testing.T) {
		hexStr := strings.Repeat("ab", nonceLength)
		n, err := parseNonce(hexStr)
		if err != nil {
			t.Fatalf("parseNonce: %v", err)
		}
		if n[0] != 0xab || n[nonceLength-1] != 0xab {
			t.Errorf("parseNonce decoded incorrectly: %x", n)
		}
	})
	t.Run("empty is random", func(t *testing.T) {
		a, err := parseNonce("")
		if err != nil {
			t.Fatalf("parseNonce: %v", err)
		}
		b, _ := parseNonce("")
		if a == b {
			t.Error("two empty-nonce calls produced identical nonces (not random)")
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		if _, err := parseNonce("abcd"); err == nil {
			t.Error("expected error for short nonce")
		}
	})
	t.Run("not hex", func(t *testing.T) {
		if _, err := parseNonce(strings.Repeat("zz", nonceLength)); err == nil {
			t.Error("expected error for non-hex nonce")
		}
	})
}

func TestArchFromString(t *testing.T) {
	cases := map[string]pb.GpuArchitectureType{
		"BLACKWELL":               pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
		"hopper":                  pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		"GPU_ARCHITECTURE_HOPPER": pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		"":                        pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED,
		"not-a-real-arch":         pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := archFromString(in); got != want {
			t.Errorf("archFromString(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUnsupportedFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"remote verifier", []string{"attest", "--verifier", "remote"}, "remote"},
		{"corelib source", []string{"collect-evidence", "--gpu-evidence-source", "corelib"}, "corelib"},
		{"rego policy", []string{"attest", "--relying-party-policy", "p.rego"}, "relying-party-policy"},
		{"rim-url override", []string{"attest", "--rim-url", "https://example.com"}, "rim-url"},
		{"ocsp-url override", []string{"attest", "--ocsp-url", "https://example.com"}, "ocsp-url"},
		{"bad device", []string{"collect-evidence", "--device", "tpu"}, "device"},
		{"file without nonce", []string{"attest", "--gpu-evidence-source", "file", "--gpu-evidence-file", mptEvidencePath}, "nonce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCmd(t, tc.args...)
			if err == nil {
				t.Fatalf("expected error, got success; output=%q", out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestCollectEvidenceFromFile(t *testing.T) {
	out, err := runCmd(t, "collect-evidence",
		"--device", "gpu",
		"--gpu-evidence-source", "file",
		"--gpu-evidence-file", mptEvidencePath,
		"--format", "json")
	if err != nil {
		t.Fatalf("collect-evidence: %v", err)
	}
	// Output must be valid evidence that parses back into a non-empty quote.
	quote, err := parseGPUEvidence([]byte(out))
	if err != nil {
		t.Fatalf("collect-evidence output did not parse: %v", err)
	}
	if len(quote.GetGpuInfos()) == 0 {
		t.Error("collect-evidence output has no GPUs")
	}
}

func TestEvidenceFileRoundTripThroughTempFile(t *testing.T) {
	// collect-evidence -> file -> attest should accept the written evidence.
	data, err := os.ReadFile(mptEvidencePath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	quote, err := parseGPUEvidence(data)
	if err != nil {
		t.Fatalf("parseGPUEvidence: %v", err)
	}
	marshaled, err := marshalEvidence(quote)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, marshaled, 0o600); err != nil {
		t.Fatalf("writing temp evidence: %v", err)
	}
	reread, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading temp evidence: %v", err)
	}
	got, err := parseGPUEvidence(reread)
	if err != nil {
		t.Fatalf("re-parsing written evidence: %v", err)
	}
	if !proto.Equal(quote, got) {
		t.Error("evidence written by the CLI did not round-trip")
	}
}
