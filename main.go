package main

import (
	"fmt"
	"os"

	"github.com/exu/localvault/internal/cli"
)

func main() {
	dir, err := cli.DefaultDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "localvault:", err)
		os.Exit(1)
	}
	app := &cli.App{Dir: dir, In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	if err := app.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "localvault:", err)
		os.Exit(1)
	}
}
