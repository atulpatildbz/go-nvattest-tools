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
	"fmt"
	"os"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/spf13/cobra"
)

// Device flag values.
const (
	deviceGPU      = "gpu"
	deviceNVSwitch = "nvswitch"
)

// Evidence source flag values.
const (
	sourceNVML    = "nvml"
	sourceNSCQ    = "nscq"
	sourceFile    = "file"
	sourceCorelib = "corelib"
)

// evidenceFlags holds the flags shared by `collect-evidence` and `attest` that
// determine how device evidence is obtained.
type evidenceFlags struct {
	device               string
	nonce                string
	gpuEvidenceSource    string
	gpuEvidenceFile      string
	nvswitchEvidenceSrc  string
	nvswitchEvidenceFile string
	gpuArchitecture      string
}

// addEvidenceFlags registers the evidence-acquisition flags on a command.
func (e *evidenceFlags) addEvidenceFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&e.device, "device", deviceGPU, "device to attest: gpu, nvswitch")
	f.StringVar(&e.nonce, "nonce", "", "attestation nonce in hex (32 bytes); random if omitted")
	f.StringVar(&e.gpuEvidenceSource, "gpu-evidence-source", sourceNVML, "GPU evidence source: nvml, file (corelib not supported)")
	f.StringVar(&e.gpuEvidenceFile, "gpu-evidence-file", "", "GPU evidence JSON file (when --gpu-evidence-source file)")
	f.StringVar(&e.nvswitchEvidenceSrc, "nvswitch-evidence-source", sourceNSCQ, "NVSwitch evidence source: nscq, file")
	f.StringVar(&e.nvswitchEvidenceFile, "nvswitch-evidence-file", "", "NVSwitch evidence JSON file (when --nvswitch-evidence-source file)")
	f.StringVar(&e.gpuArchitecture, "gpu-architecture", "", "GPU architecture (accepted for compatibility; derived from evidence)")
}

// acquireGPUQuote obtains a GPU attestation quote from the configured source.
func (e *evidenceFlags) acquireGPUQuote(nonce [nonceLength]byte) (*pb.GpuAttestationQuote, error) {
	switch e.gpuEvidenceSource {
	case sourceFile:
		if e.gpuEvidenceFile == "" {
			return nil, fmt.Errorf("--gpu-evidence-file is required when --gpu-evidence-source is file")
		}
		data, err := os.ReadFile(e.gpuEvidenceFile)
		if err != nil {
			return nil, fmt.Errorf("reading GPU evidence file: %w", err)
		}
		return parseGPUEvidence(data)
	case sourceNVML:
		provider := newGPUProvider()
		if provider == nil {
			return nil, fmt.Errorf("live GPU evidence collection (nvml) is only supported on Linux; use --gpu-evidence-source file")
		}
		return provider.CollectGpuEvidence(nonce)
	case sourceCorelib:
		return nil, fmt.Errorf("--gpu-evidence-source corelib is not supported")
	default:
		return nil, fmt.Errorf("invalid --gpu-evidence-source %q: must be one of nvml, file", e.gpuEvidenceSource)
	}
}

// acquireSwitchQuote obtains an NVSwitch attestation quote from the configured source.
func (e *evidenceFlags) acquireSwitchQuote(nonce [nonceLength]byte) (*pb.SwitchAttestationQuote, error) {
	switch e.nvswitchEvidenceSrc {
	case sourceFile:
		if e.nvswitchEvidenceFile == "" {
			return nil, fmt.Errorf("--nvswitch-evidence-file is required when --nvswitch-evidence-source is file")
		}
		data, err := os.ReadFile(e.nvswitchEvidenceFile)
		if err != nil {
			return nil, fmt.Errorf("reading NVSwitch evidence file: %w", err)
		}
		return parseSwitchEvidence(data)
	case sourceNSCQ:
		provider := newSwitchProvider()
		if provider == nil {
			return nil, fmt.Errorf("live NVSwitch evidence collection (nscq) is only supported on Linux; use --nvswitch-evidence-source file")
		}
		return provider.CollectSwitchEvidence(nonce)
	default:
		return nil, fmt.Errorf("invalid --nvswitch-evidence-source %q: must be one of nscq, file", e.nvswitchEvidenceSrc)
	}
}

// newCollectEvidenceCmd builds the `collect-evidence` subcommand.
func newCollectEvidenceCmd(g *globalOptions) *cobra.Command {
	e := &evidenceFlags{}
	cmd := &cobra.Command{
		Use:   "collect-evidence",
		Short: "Collect device attestation evidence from live devices or a file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			nonce, err := parseNonce(e.nonce)
			if err != nil {
				return err
			}

			switch e.device {
			case deviceGPU:
				quote, err := e.acquireGPUQuote(nonce)
				if err != nil {
					return err
				}
				return writeEvidence(cmd, g, quote)
			case deviceNVSwitch:
				quote, err := e.acquireSwitchQuote(nonce)
				if err != nil {
					return err
				}
				return writeEvidence(cmd, g, quote)
			default:
				return fmt.Errorf("invalid --device %q: must be one of gpu, nvswitch", e.device)
			}
		},
	}
	e.addEvidenceFlags(cmd)
	return cmd
}
