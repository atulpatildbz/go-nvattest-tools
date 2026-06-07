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

// Package cli implements the `nvattest` command-line interface. The command
// surface (subcommands, flags and defaults) intentionally mirrors NVIDIA's
// attestation-sdk `nvattest` tool. This library only implements local
// verification, so the remote (NRAS) verifier and signed EAT/JWT output are not
// supported; see the per-flag documentation for details.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the nvattest CLI version reported by the `version` subcommand.
const Version = "1.0"

// formatText and formatJSON are the supported values for the --format flag.
const (
	formatText = "text"
	formatJSON = "json"
)

var validLogLevels = map[string]bool{
	"trace": true, "debug": true, "info": true, "warn": true, "error": true, "off": true,
}

// globalOptions holds the persistent flags shared by every subcommand.
type globalOptions struct {
	logLevel string
	format   string
}

func (g *globalOptions) validate() error {
	if !validLogLevels[g.logLevel] {
		return fmt.Errorf("invalid --log-level %q: must be one of trace, debug, info, warn, error, off", g.logLevel)
	}
	if g.format != formatText && g.format != formatJSON {
		return fmt.Errorf("invalid --format %q: must be one of text, json", g.format)
	}
	return nil
}

// newRootCmd builds the root `nvattest` command and wires up its subcommands.
func newRootCmd() *cobra.Command {
	g := &globalOptions{}

	root := &cobra.Command{
		Use:   "nvattest",
		Short: "Collect and verify NVIDIA GPU and NVSwitch attestation evidence",
		Long: "nvattest collects device attestation evidence and verifies the " +
			"integrity of NVIDIA GPUs and NVSwitches using local attestation.",
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return g.validate()
		},
	}

	root.PersistentFlags().StringVar(&g.logLevel, "log-level", "warn",
		"log verbosity: trace, debug, info, warn, error, off")
	root.PersistentFlags().StringVar(&g.format, "format", formatText,
		"output format: text, json")

	root.AddCommand(
		newVersionCmd(g),
		newCollectEvidenceCmd(g),
		newAttestCmd(g),
	)

	return root
}

// Execute runs the nvattest CLI. It returns a non-nil error if the command
// failed; the error has already been printed to stderr by cobra.
func Execute() error {
	return newRootCmd().Execute()
}
