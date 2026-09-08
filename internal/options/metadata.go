package options

import (
	"errors"
	"os"
)

type MetadataOptions struct {
	Certificates []string
	OutputFile   string
	Password     string
	Verbose      bool
}

func (opts *MetadataOptions) Validate() error {
	certCount := len(opts.Certificates)
	if certCount != 1 {
		return errors.New("you must only provide one certificate file (-c)")
	}
	if opts.OutputFile == "" {
		return errors.New("you must provide an output file (-o)")
	}
	if opts.Password == "" {
		if os.Getenv("sslpass") == "changeit" {
			return errors.New("Password is not set")
		} else if os.Getenv("sslpass") == "" {
			opts.Password = "changeit"
		} else {
			opts.Password = os.Getenv("sslpass")
		}
		//opts.Password = os.Getenv("sslpass")
	}

	return nil
}
