package options

import (
	"errors"
	"os"
)

type FinishOptions struct {
	Certificate string
	Key         string
	PfxFile     string
	Password    string
	Chain       bool
	IncludeRoot bool
	Verbose     bool
}

func (opts *FinishOptions) Validate() error {
	if opts.Certificate == "" {
		return errors.New("Certificate file (-c) is required")
	}
	if opts.Key == "" {
		return errors.New("Key file (-k) is required")
	}
	if opts.Password == "" {
		if os.Getenv("sslpass") == "" {
			return errors.New("Password is not set")
		}
		opts.Password = os.Getenv("sslpass")
	}
	if opts.IncludeRoot && !opts.Chain {
		return errors.New("--chain flag must be enabled to use --include-root flag")
	}
	return nil
}
