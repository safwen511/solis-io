package main

import (
	"fmt"
	"os"

	"github.com/safwen511/solis-io/internal/cli"
)

// main runs the package entry point and reports failures through its configured process contract.
func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
