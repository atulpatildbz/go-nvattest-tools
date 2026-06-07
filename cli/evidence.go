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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// nonceLength is the size in bytes of an attestation nonce.
const nonceLength = 32

// Legacy evidence JSON structs. These mirror the format produced by NVIDIA's
// attestation-sdk / nvtrust tooling (and the fixtures under testing/testdata),
// so evidence files collected with those tools can be consumed directly.
type legacyCertificate struct {
	Pem string `json:"pem,omitempty"`
}

type legacyReport struct {
	B64Str string `json:"py/b64,omitempty"`
}

type legacyGPUCertChain struct {
	Certificates []legacyCertificate `json:"GpuAttestationCertificateChain,omitempty"`
}

type legacyGPU struct {
	UUID              string             `json:"UUID,omitempty"`
	DriverVersion     string             `json:"DriverVersion,omitempty"`
	VBiosVersion      string             `json:"VbiosVersion,omitempty"`
	Arch              string             `json:"Arch,omitempty"`
	CertificateChains legacyGPUCertChain `json:"CertificateChains,omitempty"`
	AttestationReport legacyReport       `json:"AttestationReport,omitempty"`
}

type legacySwitch struct {
	UUID              string              `json:"uuid,omitempty"`
	CertificateChains []legacyCertificate `json:"attestation_cert_chain,omitempty"`
	AttestationReport legacyReport        `json:"attestation_report,omitempty"`
}

type legacyEvidence struct {
	Gpus       []legacyGPU    `json:"gpus,omitempty"`
	NvSwitches []legacySwitch `json:"nvswitches,omitempty"`
}

// archFromString maps a short architecture name (e.g. "BLACKWELL", "HOPPER") to
// the proto enum. Unknown values map to UNSPECIFIED.
func archFromString(s string) pb.GpuArchitectureType {
	if s == "" {
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED
	}
	key := strings.ToUpper(s)
	if !strings.HasPrefix(key, "GPU_ARCHITECTURE_") {
		key = "GPU_ARCHITECTURE_" + key
	}
	if v, ok := pb.GpuArchitectureType_value[key]; ok {
		return pb.GpuArchitectureType(v)
	}
	return pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED
}

// decodeCertChain base64-decodes each PEM entry and concatenates them into the
// single byte blob the verification library expects.
func decodeCertChain(b64Pems []string) ([]byte, error) {
	var chain []byte
	for _, p := range b64Pems {
		der, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("decoding certificate: %w", err)
		}
		chain = append(chain, der...)
	}
	return chain, nil
}

// parseGPUEvidence parses GPU evidence JSON into a quote, accepting either the
// protojson form written by this CLI or the legacy NVIDIA evidence format.
func parseGPUEvidence(data []byte) (*pb.GpuAttestationQuote, error) {
	// Prefer protojson; it errors on unknown fields, so legacy files fall through.
	quote := &pb.GpuAttestationQuote{}
	if err := protojson.Unmarshal(data, quote); err == nil {
		return quote, nil
	}

	var legacy legacyEvidence
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("parsing GPU evidence (tried protojson and legacy formats): %w", err)
	}
	if len(legacy.Gpus) == 0 {
		return nil, fmt.Errorf("GPU evidence contains no GPUs")
	}

	infos := make([]*pb.GpuInfo, 0, len(legacy.Gpus))
	for _, g := range legacy.Gpus {
		pems := make([]string, 0, len(g.CertificateChains.Certificates))
		for _, c := range g.CertificateChains.Certificates {
			pems = append(pems, c.Pem)
		}
		chain, err := decodeCertChain(pems)
		if err != nil {
			return nil, fmt.Errorf("GPU %q: %w", g.UUID, err)
		}
		report, err := base64.StdEncoding.DecodeString(g.AttestationReport.B64Str)
		if err != nil {
			return nil, fmt.Errorf("GPU %q: decoding attestation report: %w", g.UUID, err)
		}
		infos = append(infos, &pb.GpuInfo{
			Uuid:                        g.UUID,
			DriverVersion:               g.DriverVersion,
			VbiosVersion:                g.VBiosVersion,
			GpuArchitecture:             archFromString(g.Arch),
			AttestationCertificateChain: chain,
			AttestationReport:           report,
		})
	}
	return &pb.GpuAttestationQuote{GpuInfos: infos}, nil
}

// parseSwitchEvidence parses NVSwitch evidence JSON, accepting either the
// protojson form written by this CLI or the legacy NVIDIA evidence format.
func parseSwitchEvidence(data []byte) (*pb.SwitchAttestationQuote, error) {
	quote := &pb.SwitchAttestationQuote{}
	if err := protojson.Unmarshal(data, quote); err == nil {
		return quote, nil
	}

	var legacy legacyEvidence
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("parsing NVSwitch evidence (tried protojson and legacy formats): %w", err)
	}
	if len(legacy.NvSwitches) == 0 {
		return nil, fmt.Errorf("NVSwitch evidence contains no switches")
	}

	infos := make([]*pb.SwitchInfo, 0, len(legacy.NvSwitches))
	for _, s := range legacy.NvSwitches {
		pems := make([]string, 0, len(s.CertificateChains))
		for _, c := range s.CertificateChains {
			pems = append(pems, c.Pem)
		}
		chain, err := decodeCertChain(pems)
		if err != nil {
			return nil, fmt.Errorf("NVSwitch %q: %w", s.UUID, err)
		}
		report, err := base64.StdEncoding.DecodeString(s.AttestationReport.B64Str)
		if err != nil {
			return nil, fmt.Errorf("NVSwitch %q: decoding attestation report: %w", s.UUID, err)
		}
		infos = append(infos, &pb.SwitchInfo{
			Uuid:                        s.UUID,
			AttestationCertificateChain: chain,
			AttestationReport:           report,
		})
	}
	return &pb.SwitchAttestationQuote{SwitchInfos: infos}, nil
}

// marshalEvidence serializes a quote to indented protojson, the format consumed
// by parse*Evidence so that `collect-evidence` output can feed back into
// `attest --gpu-evidence-source file`.
func marshalEvidence(m proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
}

// parseNonce decodes a hex nonce string into a fixed 32-byte array. An empty
// string yields a freshly generated random nonce.
func parseNonce(hexStr string) ([nonceLength]byte, error) {
	var nonce [nonceLength]byte
	if hexStr == "" {
		if _, err := rand.Read(nonce[:]); err != nil {
			return nonce, fmt.Errorf("generating random nonce: %w", err)
		}
		return nonce, nil
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nonce, fmt.Errorf("invalid --nonce %q: must be hex-encoded: %w", hexStr, err)
	}
	if len(raw) != nonceLength {
		return nonce, fmt.Errorf("invalid --nonce: must be %d bytes (%d hex chars), got %d bytes", nonceLength, nonceLength*2, len(raw))
	}
	copy(nonce[:], raw)
	return nonce, nil
}
