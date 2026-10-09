package cli

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"

	"github.com/spf13/cobra"

	"github.com/exu/localvault/internal/vault"
)

var envRef = regexp.MustCompile(`\$env\[([A-Za-z_][A-Za-z0-9_]*)\]`)

func (a *App) listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secret names",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _, secrets, err := a.openSession()
			if err != nil {
				return err
			}
			keys := make([]string, 0, len(secrets))
			for k := range secrets {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintln(cmd.OutOrStdout(), k)
			}
			return nil
		},
	}
}

func (a *App) deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete KEY",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, dek, secrets, err := a.openSession()
			if err != nil {
				return err
			}
			if _, ok := secrets[args[0]]; !ok {
				return fmt.Errorf("key %q not found", args[0])
			}
			delete(secrets, args[0])
			nf, err := vault.Seal(dek, secrets, f.Unlockers)
			if err != nil {
				return err
			}
			return vault.Save(a.vaultPath(), nf)
		},
	}
}

// runCmd runs a shell command with $env[NAME] references exposed as child env vars, keeping values out of argv and scrubbing stored values from its output.
func (a *App) runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run 'command with $env[KEY]'",
		Short: "Run a shell command with secrets injected as environment variables",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, secrets, err := a.openSession()
			if err != nil {
				return err
			}
			env := os.Environ()
			for _, m := range envRef.FindAllStringSubmatch(args[0], -1) {
				v, ok := secrets[m[1]]
				if !ok {
					return fmt.Errorf("key %q not found", m[1])
				}
				env = append(env, m[1]+"="+v)
			}
			script := envRef.ReplaceAllString(args[0], `$$$1`)
			c := exec.Command("sh", "-c", script)
			c.Env = env
			c.Stdin = cmd.InOrStdin()
			stdout, skipped := newRedactor(cmd.OutOrStdout(), secrets)
			stderr, _ := newRedactor(cmd.ErrOrStderr(), secrets)
			c.Stdout, c.Stderr = stdout, stderr
			for _, n := range skipped {
				fmt.Fprintf(cmd.ErrOrStderr(), "localvault: %s is too short to redact from output\n", n)
			}
			runErr := c.Run()
			if err := stdout.Close(); err != nil {
				return err
			}
			if err := stderr.Close(); err != nil {
				return err
			}
			return runErr
		},
	}
}
