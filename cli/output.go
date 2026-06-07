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
	"encoding/json"
	"fmt"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

// writeEvidence renders a collected quote. Under --format json the evidence is
// emitted as protojson (re-readable via --gpu-evidence-source file); under text
// a short human-readable summary is printed.
func writeEvidence(cmd *cobra.Command, g *globalOptions, quote proto.Message) error {
	w := cmd.OutOrStdout()

	if g.format == formatJSON {
		out, err := marshalEvidence(quote)
		if err != nil {
			return fmt.Errorf("serializing evidence: %w", err)
		}
		fmt.Fprintln(w, string(out))
		return nil
	}

	switch q := quote.(type) {
	case *pb.GpuAttestationQuote:
		fmt.Fprintf(w, "Collected evidence for %d GPU(s):\n", len(q.GetGpuInfos()))
		for _, gi := range q.GetGpuInfos() {
			fmt.Fprintf(w, "  - %s (driver %s, vbios %s, arch %s)\n",
				gi.GetUuid(), gi.GetDriverVersion(), gi.GetVbiosVersion(), gi.GetGpuArchitecture())
		}
	case *pb.SwitchAttestationQuote:
		fmt.Fprintf(w, "Collected evidence for %d NVSwitch(es):\n", len(q.GetSwitchInfos()))
		for _, si := range q.GetSwitchInfos() {
			fmt.Fprintf(w, "  - %s\n", si.GetUuid())
		}
	}
	fmt.Fprintln(w, "(use --format json to emit reusable evidence)")
	return nil
}

// writeResult renders the verification result for the attest command. Either
// state may be nil depending on the device(s) attested.
func writeResult(cmd *cobra.Command, g *globalOptions, gpuState *pb.GpuQuoteState, switchState *pb.SwitchQuoteState) error {
	w := cmd.OutOrStdout()

	if g.format == formatJSON {
		obj := map[string]json.RawMessage{}
		if gpuState != nil {
			raw, err := protojsonRaw(gpuState)
			if err != nil {
				return err
			}
			obj["gpu"] = raw
		}
		if switchState != nil {
			raw, err := protojsonRaw(switchState)
			if err != nil {
				return err
			}
			obj["nvswitch"] = raw
		}
		out, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(out))
		return nil
	}

	if gpuState != nil {
		fmt.Fprintf(w, "GPU verification (%d device(s)):\n", len(gpuState.GetGpuInfoStates()))
		for _, s := range gpuState.GetGpuInfoStates() {
			fmt.Fprintf(w, "  - %s: nonce_match=%t signature_verified=%t measurements_matched=%t\n",
				s.GetGpuUuid(), s.GetNonceMatch(), s.GetSignatureVerified(), s.GetMeasurementsMatched())
		}
	}
	if switchState != nil {
		fmt.Fprintf(w, "NVSwitch verification (%d device(s)):\n", len(switchState.GetSwitchInfoStates()))
		for _, s := range switchState.GetSwitchInfoStates() {
			fmt.Fprintf(w, "  - %s: nonce_match=%t signature_verified=%t measurements_matched=%t\n",
				s.GetSwitchUuid(), s.GetNonceMatch(), s.GetSignatureVerified(), s.GetMeasurementsMatched())
		}
	}
	return nil
}

// protojsonRaw marshals a proto message to a json.RawMessage using protojson.
func protojsonRaw(m proto.Message) (json.RawMessage, error) {
	b, err := marshalEvidence(m)
	if err != nil {
		return nil, fmt.Errorf("serializing result: %w", err)
	}
	return json.RawMessage(b), nil
}
