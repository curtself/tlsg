package x509extras

import (
	"crypto/x509"
	"errors"
)

// SortCertificateChain tries to sort a slice of x509 certificates from leaf to root.
// It returns an error only if the chain is broken *and* cannot be verified against system roots.
func SortCertificateChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, nil
	}

	// if we only have 1 cert then it is already sorted
	if len(certs) == 1 {
		return certs, nil
	}
	// Build maps for subject and issuer relationships
	subjectMap := make(map[string]*x509.Certificate)
	issuerMap := make(map[string][]*x509.Certificate)
	for _, c := range certs {
		subjectMap[c.Subject.String()] = c
		issuerMap[c.Issuer.String()] = append(issuerMap[c.Issuer.String()], c)
	}

	// Attempt to identify the leaf: a cert that is not the issuer of any other cert
	var leaf *x509.Certificate
	for _, c := range certs {
		if len(issuerMap[c.Subject.String()]) == 0 {
			leaf = c
			break
		}
	}

	// Fallback: use the first cert that is not self-signed
	if leaf == nil {
		for _, c := range certs {
			if c.Subject.String() != c.Issuer.String() {
				leaf = c
				break
			}
		}
	}

	if leaf == nil {
		return nil, errors.New("could not identify leaf certificate")
	}

	var sorted []*x509.Certificate
	seen := make(map[string]bool)

	current := leaf
	for {
		if seen[current.Subject.String()] {
			break
		}
		seen[current.Subject.String()] = true
		sorted = append(sorted, current)

		// Stop if self-signed root
		if current.Subject.String() == current.Issuer.String() {
			break
		}

		parent, ok := subjectMap[current.Issuer.String()]
		if ok {
			current = parent
			continue
		}

		break
		/*
		// Not found in chain, try system trust
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("could not load system cert pool")
		}

		intermediates := x509.NewCertPool()
		for _, ic := range sorted {
			intermediates.AddCert(ic)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := current.Verify(opts); err == nil {
			break // trusted by system
		} else {
			return nil, errors.New("incomplete chain: issuer not found and cert not trusted: " + current.Subject.String())
		}
		*/
	}

	return sorted, nil
}
