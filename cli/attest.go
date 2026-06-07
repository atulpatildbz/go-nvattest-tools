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
	"context"
	"fmt"

	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/mpt"
	ppcie "github.com/google/go-nvattest-tools/ppcie/server"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	nvattestocsp "github.com/google/go-nvattest-tools/server/ocsp"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	"github.com/google/go-nvattest-tools/spt"
	"github.com/spf13/cobra"
)

// Verifier flag values.
const (
	verifierLocal  = "local"
	verifierRemote = "remote"
)

// defaultMaxCertChainLength is the expected attestation certificate chain length
// (leaf..root). Matches the value used in the library's documented examples.
const defaultMaxCertChainLength = 5

// attestFlags holds the attest-specific flags in addition to the shared
// evidence flags.
type attestFlags struct {
	evidenceFlags
	verifier           string
	rimURL             string
	ocspURL            string
	nrasURL            string
	serviceKey         string
	relyingPartyPolicy string
}

// newAttestCmd builds the `attest` subcommand.
func newAttestCmd(g *globalOptions) *cobra.Command {
	a := &attestFlags{}
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Verify device attestation evidence and report verification claims",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.run(cmd, g)
		},
	}
	a.addEvidenceFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&a.verifier, "verifier", verifierLocal, "verification method: local (remote/NRAS is not supported)")
	f.StringVar(&a.rimURL, "rim-url", "", "RIM service base URL (override not supported; uses NVIDIA default)")
	f.StringVar(&a.ocspURL, "ocsp-url", "", "OCSP responder base URL (override not supported; uses NVIDIA default)")
	f.StringVar(&a.nrasURL, "nras-url", "", "NRAS base URL (accepted for compatibility; ignored for local verification)")
	f.StringVar(&a.serviceKey, "service-key", "", "service key for authenticating to NVIDIA RIM/OCSP services")
	f.StringVar(&a.relyingPartyPolicy, "relying-party-policy", "", "Rego relying-party policy file (not supported)")
	return cmd
}

// validateFlags rejects flag combinations this CLI does not support.
func (a *attestFlags) validateFlags() error {
	switch a.verifier {
	case verifierLocal:
		// supported
	case verifierRemote:
		return fmt.Errorf("--verifier remote (NRAS) is not supported; only local verification is available")
	default:
		return fmt.Errorf("invalid --verifier %q: must be local", a.verifier)
	}
	if a.relyingPartyPolicy != "" {
		return fmt.Errorf("--relying-party-policy (Rego) is not supported")
	}
	if a.rimURL != "" {
		return fmt.Errorf("--rim-url override is not supported; the NVIDIA default RIM service is always used")
	}
	if a.ocspURL != "" {
		return fmt.Errorf("--ocsp-url override is not supported; the NVIDIA default OCSP service is always used")
	}
	return nil
}

func (a *attestFlags) run(cmd *cobra.Command, g *globalOptions) error {
	if err := a.validateFlags(); err != nil {
		return err
	}

	// Evidence read from a file was collected with a specific nonce that we must
	// know to verify it, so require an explicit --nonce in that case.
	if a.device == deviceGPU && a.gpuEvidenceSource == sourceFile && a.nonce == "" {
		return fmt.Errorf("--nonce is required when verifying GPU evidence from a file")
	}
	if a.device == deviceNVSwitch && a.nvswitchEvidenceSrc == sourceFile && a.nonce == "" {
		return fmt.Errorf("--nonce is required when verifying NVSwitch evidence from a file")
	}

	nonce, err := parseNonce(a.nonce)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	switch a.device {
	case deviceGPU:
		return a.attestGPU(ctx, cmd, g, nonce)
	case deviceNVSwitch:
		return a.attestSwitch(ctx, cmd, g, nonce)
	default:
		return fmt.Errorf("invalid --device %q: must be one of gpu, nvswitch", a.device)
	}
}

// verifyOptions builds the verification options, wiring service-key-authenticated
// RIM/OCSP clients when a key is provided.
func (a *attestFlags) verifyOptions(arch pb.GpuArchitectureType) verify.Options {
	opts := verify.Options{
		GpuOpts:    verify.GPUOpts{GPUArch: arch, MaxCertChainLength: defaultMaxCertChainLength},
		SwitchOpts: verify.SwitchOpts{MaxCertChainLength: defaultMaxCertChainLength},
	}
	if a.serviceKey != "" {
		opts.RimClient = rim.NewDefaultNvidiaClient(nil, a.serviceKey)
		opts.OcspClient = nvattestocsp.NewDefaultNvidiaClient(nil, a.serviceKey)
	}
	return opts
}

// validateOptions builds the measurement-validation options for the given
// attestation type.
func (a *attestFlags) validateOptions(nonce [nonceLength]byte, at abi.AttestationType, arch pb.GpuArchitectureType) validate.Options {
	opts := validate.Options{
		Nonce:           nonce[:],
		AttestationType: at,
		GpuArch:         arch,
	}
	if a.serviceKey != "" {
		opts.RimClient = rim.NewDefaultNvidiaClient(nil, a.serviceKey)
	}
	return opts
}

func (a *attestFlags) attestGPU(ctx context.Context, cmd *cobra.Command, g *globalOptions, nonce [nonceLength]byte) error {
	gpuQuote, err := a.acquireGPUQuote(nonce)
	if err != nil {
		return err
	}
	if len(gpuQuote.GetGpuInfos()) == 0 {
		return fmt.Errorf("GPU evidence contains no GPUs")
	}

	arch := gpuArchitecture(gpuQuote, a.gpuArchitecture)
	mode := detectMode(gpuQuote.GetGpuInfos()[0].GetAttestationReport())

	switch mode {
	case abi.PPCIEMode:
		// PPCIE attestation needs the matching NVSwitch evidence as well.
		switchQuote, err := a.acquireSwitchQuote(nonce)
		if err != nil {
			return fmt.Errorf("PPCIE attestation requires NVSwitch evidence: %w", err)
		}
		opts := ppcie.Options{
			VerificationOpts:       a.verifyOptions(arch),
			GPUValidationOpts:      a.validateOptions(nonce, abi.GPU, arch),
			NVSwitchValidationOpts: a.validateOptions(nonce, abi.SWITCH, arch),
			ExpectedGpuCount:       len(gpuQuote.GetGpuInfos()),
			ExpectedSwitchCount:    len(switchQuote.GetSwitchInfos()),
		}
		gpuState, switchState, err := ppcie.VerifySystemQuotes(ctx, gpuQuote, switchQuote, opts)
		if werr := writeResult(cmd, g, gpuState, switchState); werr != nil {
			return werr
		}
		return err
	case abi.MPTMode:
		gpuState, verr := mpt.VerifySystemQuotes(ctx, gpuQuote, mpt.Options{
			Verification: a.verifyOptions(arch),
			Validation:   a.validateOptions(nonce, abi.GPU, arch),
		})
		if werr := writeResult(cmd, g, gpuState, nil); werr != nil {
			return werr
		}
		return verr
	default:
		// SPT or legacy: verify each GPU independently.
		gpuState := &pb.GpuQuoteState{}
		var firstErr error
		for _, gpuInfo := range gpuQuote.GetGpuInfos() {
			state, verr := spt.VerifyGpuQuote(ctx, gpuInfo, spt.Options{
				Verification: a.verifyOptions(arch),
				Validation:   a.validateOptions(nonce, abi.GPU, arch),
			})
			if verr != nil {
				if firstErr == nil {
					firstErr = verr
				}
				continue
			}
			gpuState.GpuInfoStates = append(gpuState.GpuInfoStates, state)
		}
		if werr := writeResult(cmd, g, gpuState, nil); werr != nil {
			return werr
		}
		return firstErr
	}
}

func (a *attestFlags) attestSwitch(ctx context.Context, cmd *cobra.Command, g *globalOptions, nonce [nonceLength]byte) error {
	switchQuote, err := a.acquireSwitchQuote(nonce)
	if err != nil {
		return err
	}
	if len(switchQuote.GetSwitchInfos()) == 0 {
		return fmt.Errorf("NVSwitch evidence contains no switches")
	}

	vopts := a.verifyOptions(pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED)
	valOpts := a.validateOptions(nonce, abi.SWITCH, pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED)

	switchState := &pb.SwitchQuoteState{}
	var firstErr error
	for _, switchInfo := range switchQuote.GetSwitchInfos() {
		state, verr := verify.SwitchInfo(ctx, switchInfo, vopts)
		if verr != nil {
			if firstErr == nil {
				firstErr = verr
			}
			continue
		}
		// The BIOS version is only known after verification (extracted from the
		// opaque data), mirroring ppcie.VerifySystemQuotes.
		opts := valOpts
		opts.VBiosVersion = state.GetBiosVersion()
		if verr := validate.AttestationReport(ctx, switchInfo.GetAttestationReport(), opts); verr != nil {
			if firstErr == nil {
				firstErr = verr
			}
		} else if !opts.DisableRefCheck {
			state.MeasurementsMatched = true
		}
		switchState.SwitchInfoStates = append(switchState.SwitchInfoStates, state)
	}

	if werr := writeResult(cmd, g, nil, switchState); werr != nil {
		return werr
	}
	return firstErr
}

// gpuArchitecture returns the GPU architecture to verify against: the value
// carried in the evidence if set, otherwise the --gpu-architecture override.
func gpuArchitecture(quote *pb.GpuAttestationQuote, override string) pb.GpuArchitectureType {
	if arch := quote.GetGpuInfos()[0].GetGpuArchitecture(); arch != pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED {
		return arch
	}
	return archFromString(override)
}

// detectMode parses the attestation report to determine the topology mode
// (SPT/MPT/PPCIE). On any parse error it falls back to SPT, which verifies each
// GPU independently.
func detectMode(report []byte) string {
	parsed, err := abi.RawAttestationReportToProto(report, abi.GPU)
	if err != nil {
		return abi.SPTMode
	}
	mode, err := abi.ParseFeatureFlag(parsed)
	if err != nil {
		return abi.SPTMode
	}
	return mode
}
