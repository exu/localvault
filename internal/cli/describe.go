package cli

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// describe summarizes a command for the unlock dialog without revealing secret values.
func describe(cmd *cobra.Command, args []string) string {
	switch cmd.Name() {
	case "set":
		keys := make([]string, 0, len(args))
		for _, a := range args {
			k, _, _ := strings.Cut(a, "=")
			keys = append(keys, k)
		}
		return "set " + strings.Join(keys, ", ")
	case "get", "delete":
		if len(args) == 1 {
			return cmd.Name() + " " + args[0]
		}
	case "run":
		if len(args) == 1 {
			c := args[0]
			if len(c) > 60 {
				c = c[:60] + "..."
			}
			return "run " + c
		}
	}
	return cmd.Name()
}

// parentName returns the name of the parent process, or "a process" if unknown.
func parentName() string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(os.Getppid())).Output()
	name := strings.TrimSpace(string(out))
	if err != nil || name == "" {
		return "a process"
	}
	name = strings.TrimPrefix(name, "-")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}
