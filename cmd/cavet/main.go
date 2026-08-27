package main

import (
	"os"

	"github.com/ChaosChild/cavet/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
