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

// Command nvattest is a CLI for collecting and verifying NVIDIA GPU and
// NVSwitch attestation evidence. Its interface mirrors NVIDIA's attestation-sdk
// `nvattest` tool so that existing users can migrate with minimal changes.
package main

import (
	"os"

	"github.com/google/go-nvattest-tools/cli"
)

func main() {
	// cli.Execute prints any error to stderr; we only need to set the exit code.
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
