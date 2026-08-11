package options

import (
	"errors"
	"os"
)

type InfoOptions struct {
	Certificates []string
	URLs         []string
	Hosts        map[string]string
	CSR          string
	ShortSummary bool
	Password     string
}

func (opts *InfoOptions) Validate() error {
	certCount := len(opts.Certificates)
	urlCount := len(opts.URLs)
	hostCount := len(opts.Hosts)
	hasCsr := len(opts.CSR) != 0
	var csrCount int
	if hasCsr {
		csrCount = 1
	}
	if certCount+urlCount+hostCount+csrCount == 0 {
		return errors.New("you must provide at least one certificate, url, host, or CSR")
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
