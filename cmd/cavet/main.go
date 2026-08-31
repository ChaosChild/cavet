// Package main builds the cavet command: advisory security tooling for
// coding agents. cavet scans a repository with the containerised cavet-engine
// (SAST, secrets, SCA), triages findings against a baseline, and records the
// result in an on-disk log — a warning, never a prohibition. Source and
// documentation: https://github.com/ChaosChild/cavet
package main

import (
	"os"

	"github.com/ChaosChild/cavet/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
