// Package cli wires the localvault commands.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/exu/localvault/internal/session"
	"github.com/exu/localvault/internal/unlocker"
	"github.com/exu/localvault/internal/vault"
)

const defaultTTL = 15 * time.Minute

var errLocked = errors.New("locked, run `localvault unlock`")

// App holds the vault directory and IO streams for the commands.
type App struct {
	Version  string
	Dir      string
	noPrompt bool
	reqDesc  string
	In       io.Reader
	Out      io.Writer
	Err      io.Writer
}

// DefaultDir returns $LOCALVAULT_DIR or ~/.localvault.
func DefaultDir() (string, error) {
	if d := os.Getenv("LOCALVAULT_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".localvault"), nil
}

func (a *App) vaultPath() string   { return filepath.Join(a.Dir, "vault.lv") }
func (a *App) sessionPath() string { return filepath.Join(a.Dir, "session") }

// NewRoot builds the root command.
func (a *App) NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "localvault",
		Short:         "Local secret vault unlocked by password",
		Version:       a.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			a.reqDesc = describe(cmd, args)
			unlocker.PromptMessage = fmt.Sprintf("%s requests: %s\nUnlocking starts a session for %s.", parentName(), a.reqDesc, defaultTTL)
		},
	}
	root.PersistentFlags().BoolVar(&a.noPrompt, "no-prompt", false, "fail when locked instead of prompting for the password")
	root.SetIn(a.In)
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	root.AddCommand(a.configureCmd(), a.setCmd(), a.getCmd(), a.unlockCmd(), a.lockCmd(), a.statusCmd(), a.listCmd(), a.deleteCmd(), a.runCmd())
	return root
}

// sessionDEK returns the DEK from a live session.
func (a *App) sessionDEK() ([]byte, error) {
	dek, _, err := session.Read(a.sessionPath())
	if errors.Is(err, session.ErrNoSession) || errors.Is(err, session.ErrExpired) {
		return nil, errLocked
	}
	return dek, err
}

// unlockWith unwraps the DEK using the named unlocker, or the default one when name is empty.
func (a *App) unlockWith(f *vault.File, name string) ([]byte, error) {
	if name == "" {
		name = defaultUnlocker(f)
	}
	entry, ok := f.Entry(name)
	if !ok {
		return nil, fmt.Errorf("unlocker %q is not enrolled, run `localvault configure --with %s`", name, name)
	}
	u, err := unlocker.Get(name)
	if err != nil {
		return nil, err
	}
	if !u.Available() {
		return nil, fmt.Errorf("unlocker %q is not available on this machine", name)
	}
	return u.Unlock(entry.Blob)
}

// defaultUnlocker prefers touchid when enrolled and available, else password.
func defaultUnlocker(f *vault.File) string {
	if _, ok := f.Entry("touchid"); ok {
		if u, err := unlocker.Get("touchid"); err == nil && u.Available() {
			return "touchid"
		}
	}
	return "password"
}

func (a *App) loadVault() (*vault.File, error) {
	f, err := vault.Load(a.vaultPath())
	if os.IsNotExist(err) {
		return nil, errors.New("no vault, run `localvault configure`")
	}
	return f, err
}

// openSession loads the vault and decrypts it with the session DEK.
func (a *App) openSession() (*vault.File, []byte, map[string]string, error) {
	f, err := a.loadVault()
	if err != nil {
		return nil, nil, nil, err
	}
	dek, err := a.sessionDEK()
	if errors.Is(err, errLocked) && !a.noPrompt {
		dek, err = a.autoUnlock(f)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	secrets, err := f.Open(dek)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, dek, secrets, nil
}

// autoUnlock prompts for the default unlocker and starts a session with the default TTL.
func (a *App) autoUnlock(f *vault.File) ([]byte, error) {
	dek, err := a.unlockWith(f, "")
	if err != nil {
		return nil, err
	}
	if _, err := f.Open(dek); err != nil {
		return nil, err
	}
	if err := session.Write(a.sessionPath(), dek, defaultTTL); err != nil {
		return nil, err
	}
	return dek, nil
}

func (a *App) configureCmd() *cobra.Command {
	var with string
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Create the vault and enroll an unlocker (default: password)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := unlocker.Get(with)
			if err != nil {
				return err
			}
			if !u.Available() {
				return fmt.Errorf("unlocker %q is not available on this machine", with)
			}
			f, err := vault.Load(a.vaultPath())
			if os.IsNotExist(err) {
				return a.createVault(cmd, u)
			}
			if err != nil {
				return err
			}
			return a.enroll(cmd, f, u)
		},
	}
	cmd.Flags().StringVar(&with, "with", "password", "unlocker to enroll ("+strings.Join(unlocker.Names(), "|")+")")
	return cmd
}

func (a *App) createVault(cmd *cobra.Command, u unlocker.Unlocker) error {
	dek, err := vault.NewDEK()
	if err != nil {
		return err
	}
	blob, err := u.Enroll(dek)
	if err != nil {
		return err
	}
	f, err := vault.Seal(dek, map[string]string{}, []vault.Entry{{Name: u.Name(), Blob: blob}})
	if err != nil {
		return err
	}
	if err := vault.Save(a.vaultPath(), f); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "vault created with %s unlocker\n", u.Name())
	return nil
}

// enroll adds or replaces u on an existing vault, authenticating via session or an enrolled unlocker.
func (a *App) enroll(cmd *cobra.Command, f *vault.File, u unlocker.Unlocker) error {
	dek, err := a.sessionDEK()
	if errors.Is(err, errLocked) {
		dek, err = a.unlockWith(f, "")
	}
	if err != nil {
		return err
	}
	secrets, err := f.Open(dek)
	if err != nil {
		return err
	}
	blob, err := u.Enroll(dek)
	if err != nil {
		return err
	}
	updated := &vault.File{Unlockers: append([]vault.Entry(nil), f.Unlockers...)}
	updated.SetEntry(vault.Entry{Name: u.Name(), Blob: blob})
	nf, err := vault.Seal(dek, secrets, updated.Unlockers)
	if err != nil {
		return err
	}
	if err := vault.Save(a.vaultPath(), nf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s unlocker enrolled\n", u.Name())
	return nil
}

func (a *App) setCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY=val [KEY=val ...]",
		Short: "Store secrets; use KEY=- to read the value from stdin",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			updates := map[string]string{}
			for _, arg := range args {
				k, v, ok := strings.Cut(arg, "=")
				if !ok || k == "" {
					return fmt.Errorf("invalid argument %q, want KEY=val", arg)
				}
				if v == "-" {
					b, err := io.ReadAll(cmd.InOrStdin())
					if err != nil {
						return err
					}
					v = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
				}
				updates[k] = v
			}
			f, dek, secrets, err := a.openSession()
			if err != nil {
				return err
			}
			for k, v := range updates {
				secrets[k] = v
			}
			nf, err := vault.Seal(dek, secrets, f.Unlockers)
			if err != nil {
				return err
			}
			return vault.Save(a.vaultPath(), nf)
		},
	}
}

func (a *App) getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get KEY",
		Short: "Print a secret value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, secrets, err := a.openSession()
			if err != nil {
				return err
			}
			v, ok := secrets[args[0]]
			if !ok {
				return fmt.Errorf("key %q not found", args[0])
			}
			fmt.Fprintln(cmd.OutOrStdout(), v)
			return nil
		},
	}
}

func (a *App) unlockCmd() *cobra.Command {
	var with string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault and start a session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ttl <= 0 {
				return errors.New("--ttl must be positive")
			}
			f, err := a.loadVault()
			if err != nil {
				return err
			}
			dek, err := a.unlockWith(f, with)
			if err != nil {
				return err
			}
			if _, err := f.Open(dek); err != nil {
				return err
			}
			if err := session.Write(a.sessionPath(), dek, ttl); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unlocked for %s\n", ttl)
			return nil
		},
	}
	cmd.Flags().StringVar(&with, "with", "", "unlocker to use (default: touchid if enrolled, else password)")
	cmd.Flags().DurationVar(&ttl, "ttl", defaultTTL, "session lifetime")
	return cmd
}

func (a *App) lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "End the session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := session.Clear(a.sessionPath()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "locked")
			return nil
		},
	}
}

func (a *App) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show session state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, exp, err := session.Read(a.sessionPath())
			if errors.Is(err, session.ErrNoSession) || errors.Is(err, session.ErrExpired) {
				fmt.Fprintln(cmd.OutOrStdout(), "locked")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unlocked, %s left\n", time.Until(exp).Round(time.Second))
			return nil
		},
	}
}
