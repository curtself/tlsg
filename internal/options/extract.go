package options

import (
    "errors"
	"os"
)

type ExtractOptions struct {
    Certificates	[]string
    OutputFile 		string
    NumExtract 		int
    SkipCount  		int
	Password		string
}

func (opts *ExtractOptions) Validate() error {
	certCount := len(opts.Certificates)
    if certCount == 0 {
        return errors.New("you must provide a certificate file (-c)")
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
