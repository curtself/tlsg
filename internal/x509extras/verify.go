package x509extras

import (
	"crypto/x509"
	"fmt"
)

func VerifyCertificateChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates supplied")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not load system certificate pool: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return chains[0], nil
}
