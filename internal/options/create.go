package options

import (
	"errors"
)

type CreateOptions struct {
	CommonName string
	SANs       []string
	KeySize    int
	Key        string
}

func (opts *CreateOptions) Validate() error {
	if opts.CommonName == "" {
		return errors.New("Common Name (-c) is required")
	}
	if opts.KeySize != 0 && opts.Key != "" {
		return errors.New("Key and Key Size cannot be used together")
	}
	return nil
}
