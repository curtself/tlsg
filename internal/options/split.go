package options

import (
	"errors"
	"os"
)

type SplitOptions struct {
	Certificate string
	OutputDir   string
	Password    string
	KeyExtract	bool
	Verbose     bool
}

func (opts *SplitOptions) Validate() error {
	if opts.Certificate == "" {
		return errors.New("you must provide a certificate file (-c)")
	}
	if opts.OutputDir == "" {
		return errors.New("you must provide an output directory (-o)")
	}
	if opts.Password == "" {
		if os.Getenv("sslpass") == "changeit" {
			return errors.New("Password is not set")
		} else if os.Getenv("sslpass") == "" {
			opts.Password = "changeit"
		} else {
			opts.Password = os.Getenv("sslpass")
		}
	}
	return nil
}
