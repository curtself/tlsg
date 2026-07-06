package certsvc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	//"log"
	"net/url"
	"os"
	"ssl-tools/internal/certformat"
	"ssl-tools/internal/certinfo"
	"ssl-tools/internal/handshake"
	"ssl-tools/internal/models"
	"ssl-tools/internal/options"
	"ssl-tools/internal/x509extras"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

type CertificateService struct {
	keySize    int
	keyCreated bool
}

func New() *CertificateService {
	return &CertificateService{keySize: 4096, keyCreated: false}
}

func (c *CertificateService) SetKeyLength(bits int) error {
	if bits != 2048 && bits != 3072 && bits != 4096 {
		return fmt.Errorf("unsupported key size %d", bits)
	}
	c.keySize = bits
	return nil
}

func (c *CertificateService) CreateCSR(opts options.CreateOptions) (*models.CSRdto, error) {
	var privateKey *rsa.PrivateKey
	var err error

	if opts.Key != "" {
		privateKey, err = loadPrivateKeyFromFile(opts.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key at %w", err)
		}
	} else {
		if opts.KeySize == 0 {
			opts.KeySize = c.keySize // use the default key size if none given
		}
		privateKey, err = rsa.GenerateKey(rand.Reader, opts.KeySize)
		c.keyCreated = true
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	// Create subject
	subj := pkix.Name{
		CommonName:         opts.CommonName,
		Organization:       []string{"San Diego Community College District"},
		OrganizationalUnit: []string{"IT"},
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Diego"},
	}

	// Subject alternative names
	sanList := append([]string{opts.CommonName}, opts.SANs...)

	// Create CSR template
	template := x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           sanList,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating CSR: %v", err)
	}

	// Encode CSR to PEM
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Encode private key to PEM
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Return the result
	return &models.CSRdto{
		RequestData: strings.TrimSpace(string(csrPem)),
		KeyData:     string(keyPem),
		Label:       strings.ReplaceAll(opts.CommonName, "*", "_"),
	}, nil
}

func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block in key file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (c *CertificateService) SaveCSRdto(dto *models.CSRdto) ([]string, error) {
	var logs []string
	// first save CSR data to file
	csrFile := fmt.Sprintf("%s.csr", dto.Label)
	f, err := os.Create(csrFile)
	check(err)
	defer f.Close()
	byteCount, err := f.Write([]byte(dto.RequestData))
	check(err)
	logs = append(logs, fmt.Sprintf("wrote %d bytes to %s", byteCount, csrFile))

	// then save key but only if the key was created by service
	if c.keyCreated {
		//write it
		keyFile := fmt.Sprintf("%s.key", dto.Label)
		k, err := os.Create(keyFile)
		check(err)
		defer k.Close()
		keyByteCount, err := k.Write([]byte(dto.KeyData))
		check(err)
		logs = append(logs, fmt.Sprintf("wrote %d bytes to %s", keyByteCount, keyFile))
	}
	return logs, nil
}

func (c *CertificateService) SavePFXdto(dto *models.PFXdto) ([]string, error) {
	var logs []string
	var pfxFile string
	if dto.FileName == "" {
		pfxFile = fmt.Sprintf("%s.pfx", dto.CommonName)
	} else {
		pfxFile = dto.FileName
	}
	f, err := os.Create(pfxFile)
	check(err)
	defer f.Close()
	byteCount, err := f.Write(dto.CertificateData)
	check(err)
	logs = append(logs, fmt.Sprintf("wrote %d bytes to %s\n", byteCount, pfxFile))

	return logs, nil
}

/*
TODO - Need to add detection of the certificate format. Current function
assumes PEM format and that may not be the case.
pseudo flow

 1. detect format [x]

 2. load certs (either pem or der) [x]

 3. sort cert chain (aka autofix-mini) [x] (certs should be sorted already by their loaders)

 4. save subject in dto [x]

 5. load key [x]

 6. parse private key [x]

 7. build output cert (with chain if options set) [x]

 8. encode to pfx [x]

    Realistically could add options for output format.
    Now it only makes a pfx but we could make PEM and DER, as there are
    some cases where a PEM chain with PEM key after is the requested format.
    If something works with PEM we should provide a DER alternative as well.
    (see notes below under TODO for suggestions on how to handle)
*/
func (c *CertificateService) FinishCSR(opts options.FinishOptions) (*models.PFXdto, error) {
	dto := &models.PFXdto{}
	// Detect certificate type
	format := certformat.CertificateFormat.Detect(opts.Certificate)
	var certs []*x509.Certificate
	var err error
	// Load the certificate (plus chain)
	switch format {
	case certformat.DER:
		if opts.Verbose {
			fmt.Println("Loading DER cert")
		}
		certs, err = loadBinaryCertsFromFile(opts.Certificate, "")
		if err != nil {
			// return error and dto
			dto.CreateMessage = "Could not load binary certificate"
			dto.OpCode = 1001
			return dto, err
		}
	case certformat.PEM:
		if opts.Verbose {
			fmt.Println("Loading PEM cert")
		}
		certs, err = loadPemCertsFromFile(opts.Certificate)
		if err != nil {
			// return error and dto
			dto.CreateMessage = "Could not load PEM certificate"
			dto.OpCode = 1002
			return dto, err
		}
	}

	// Validate that certificates were found
	if len(certs) == 0 {
		dto.CreateMessage = "No valid certificates found"
		dto.OpCode = 1003
		return dto, nil
	}
	// Show info if in verbose mode
	if opts.Verbose {
		fmt.Printf("Loaded %d certs\n", len(certs))
		outputLines := certinfo.LogChainSummary(certs)
		for _, line := range outputLines {
			fmt.Println(line)
		}
	}

	// Identify end-entity certificate
	endEntity := findEndEntityCert(certs)
	if endEntity == nil {
		dto.CreateMessage = "No unique end-entity certificate found"
		dto.OpCode = 1004
		return dto, nil
	}
	// Save subject in dto
	dto.CommonName = endEntity.Subject.CommonName

	// Read key file
	keyBytes, err := os.ReadFile(opts.Key)
	if err != nil {
		dto.CreateMessage = fmt.Sprintf("Failed to read key file: %v", err)
		dto.OpCode = 1002
		return dto, nil
	}

	// Parse private key
	var privKey any
	privKey, err = parseRSAPrivateKey(keyBytes)
	if err != nil {
		// try to parse key as PKCS8 instead
		privKey, err = parseOtherPrivateKey(keyBytes)
		if err != nil {
			dto.CreateMessage = fmt.Sprintf("Failed to parse any key from file: %v", err)
			dto.OpCode = 1005
			return dto, nil
		}
	}

	// Build certificate chain (if the --chain flag is set)
	chain := []*x509.Certificate{endEntity}
	// Only include a chain if the option is set
	if opts.Chain {
		if opts.Verbose {
			fmt.Println("Including chain...")
		}
		if !opts.IncludeRoot {
			// if we are not including root certs then filter them out
			certs = filterTrustedCerts(certs)
			if opts.Verbose {
				fmt.Printf("After filtering tursted certs we have %d left\n", len(certs))
			}
		}
		// Depending on opts.Include root the certs slice will either be all in chain or only untrusted
		for _, cert := range certs {
			if opts.Verbose {
				fmt.Printf(" >> Checking %s\n", cert.Subject.CommonName)
			}
			if opts.IncludeRoot || !isSelfSigned(cert) {
				if !cert.Equal(endEntity) {
					if opts.Verbose {
						fmt.Printf("Adding cert to chain (%s)\n", cert.Subject.CommonName)
					}
					//chain = append(chain, cert)
					chain = append([]*x509.Certificate{cert}, chain...)
				}
			}
		}
	}

	// TODO - wrap this in a check for output format. only do this if output is PFX
	//		- that would require reworking the options, since -p/--pfx is currently used
	//		- maybe (-f/--format) could be used and it defaults to pfx
	//		- and (-p/--pfx) could be updated to (-o/--output-file) where it defaults to ""
	//		- if left blank the base name could come from the CommonName like now, but the
	//		- file extension would come from the (-f/--format) flag
	// Encode to PFX
	pfxData, err := encodeToPFX(chain, privKey, opts.Password)
	if err != nil {
		dto.CreateMessage = fmt.Sprintf("Failed to create PFX: %v", err)
		dto.OpCode = 1007
		return dto, nil
	}

	dto.CertificateData = pfxData
	dto.CreateMessage = "PFX created successfully"
	return dto, nil
}

func filterTrustedCerts(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return nil
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         nil, // use system roots
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	verifyChains, err := leaf.Verify(opts)
	if err != nil {
		fmt.Printf("  >> VERIFICATION ERROR: %v\n", err)
		return chain // if verification failed, return all certs as "untrusted"
	}

	// Use only the first valid chain
	verifiedChain := verifyChains[0]
	return verifiedChain
}

func parsePEMCerts(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

func parseRSAPrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM RSA private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseOtherPrivateKey(keyData []byte) (any, error) {
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func findEndEntityCert(certs []*x509.Certificate) *x509.Certificate {
	for _, cert := range certs {
		isIssuer := false
		for _, other := range certs {
			if cert.Subject.String() == other.Issuer.String() && !cert.Equal(other) {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return cert
		}
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String()
}

func encodeToPFX(certs []*x509.Certificate, key any, password string) ([]byte, error) {
	// This requires Go's x/crypto/pkcs12 package
	// go get golang.org/x/crypto/pkcs12
	// the above line uses the 'legacy' encoder and is considered 'unsafe' (not sure why it is presented like it is the default)
	//return pkcs12.Encode(rand.Reader, key, certs[0], certs[1:], password)
	switch key.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	case *ecdh.PrivateKey:
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	if len(certs) == 1 {
		return pkcs12.Modern2023.Encode(key, certs[0], nil, password)
	} else {
		return pkcs12.Modern2023.Encode(key, certs[0], certs[1:], password)
	}
}

/**
	First build the helpers for info.
	1: isBinary (done, using the certformat.CertificateFormat type)
	2: loadBinaryCert(path) and loadPemCert(path)
	3: some type of utility to get extensions and/or ANSI values from certificates.
	   look at the C# PrintCertInfo method at line 943 for all the data I need
**/

func loadCsrFromFile(path string) (*x509.CertificateRequest, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block != nil {
		if block.Type != "CERTIFICATE REQUEST" {
			//fmt.Printf("failed to get CSR, instead got %s\n", block.Type)
			return nil, errors.New("bad PEM block type")
		}
	} else {
		return nil, errors.New("could not read PEM data")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// This function loads PEM certs from file
func loadPemCertsFromFile(path string) ([]*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Step 4: Parse certificates from PEM
	certs, err := parsePEMCerts(certBytes)
	sorted, sortErr := x509extras.SortCertificateChain(certs[:])
	if sortErr != nil {
		// here we have an error when we try to sort.
		// we can just return the unsorted certs instead
		return certs, nil
	}
	return sorted, nil

}

// This function loads DER certs from file AND sorts them
func loadBinaryCertsFromFile(path string, pass string) ([]*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, cert, chain, err := pkcs12.DecodeChain(certBytes, pass)
	if err != nil {
		//fmt.Println("TRIED TO DECODE A PKCS12 FILE AND FAILED... NEED TO TRY NORMAL BINARY CERT")
		// try to load as DER certs
		derCerts, parseErr := x509.ParseCertificates(certBytes)
		if parseErr != nil {
			return nil, parseErr
		}
		//fmt.Printf("Loaded a total of %d certs\n", len(derCerts))
		sorted, sortErr := x509extras.SortCertificateChain(derCerts[:])
		if sortErr != nil {
			for _, dc := range derCerts {
				certinfo.LogCertInfo(dc)
			}
			return nil, sortErr
		}
		return sorted, nil
	}
	certs := append([]*x509.Certificate{cert}, chain...)
	sorted, err := x509extras.SortCertificateChain(certs)
	if err != nil {
		return nil, err
	}
	return sorted, nil
}

// info section
func (c *CertificateService) GetInfo(opts options.InfoOptions) ([]string, error) {
	var logs []string
	if len(opts.Certificates) > 0 {
		for _, path := range opts.Certificates {
			format := certformat.CertificateFormat.Detect(path)
			switch format {
			case certformat.DER:
				//fmt.Println("Binary certificate file found: ", path)
				certs, err := loadBinaryCertsFromFile(path, opts.Password)
				if err == nil {
					if !opts.ShortSummary {
						for _, cert := range certs {
							logs = append(logs, certinfo.LogCertInfo(cert)...)
						}
					}
					//fmt.Println(strings.Repeat("-", 92))
					//fmt.Println("Chain summary")
					logs = append(logs, strings.Repeat("-", 92))
					logs = append(logs, "Chain summary")
					logs = append(logs, certinfo.LogChainSummary(certs)...)
					/*
						for i, cert := range certs {
							certinfo.LogCertSummary(cert, i)
						}
					*/
				} else {
					//fmt.Println(fmt.Errorf("reading certificates failed: %w", err))
					logs = append(logs, fmt.Sprintf("reading certificates failed: %v", errors.Unwrap(err)))
					return logs, err
				}
			case certformat.PEM:
				//fmt.Println("PEM certificate file found: ", path)
				certs, err := loadPemCertsFromFile(path)
				if err == nil {
					if !opts.ShortSummary {
						for _, cert := range certs {
							logs = append(logs, certinfo.LogCertInfo(cert)...)
						}
					}
					//fmt.Println(strings.Repeat("-", 92))
					//fmt.Println("Chain summary")
					logs = append(logs, strings.Repeat("-", 92))
					logs = append(logs, "Chain summary")
					logs = append(logs, certinfo.LogChainSummary(certs)...)
					/*
						for i, cert := range certs {
							certinfo.LogCertSummary(cert, i)
						}
					*/
				} else {
					//fmt.Println(fmt.Errorf("reading certificates failed: %w", err))
					logs = append(logs, fmt.Sprintf("reading certificates failed: %v", errors.Unwrap(err)))
					return logs, err
				}
			}
		}
	}
	if opts.CSR != "" {
		//fmt.Printf("reading CSR from file: %s\n", opts.CSR)
		logs = append(logs, fmt.Sprintf("reading CSR from file: %s", opts.CSR))
		csr, err := loadCsrFromFile(opts.CSR)
		if err != nil {
			//fmt.Println(fmt.Errorf("reading CSR failed: %w", err))
			logs = append(logs, fmt.Sprintf("reading CSR failed: %v", errors.Unwrap(err)))
			return logs, err
		}
		logs = append(logs, certinfo.LogCsrInfo(csr)...)
	}
	if len(opts.URLs) > 0 {
		for _, urlString := range opts.URLs {
			if !strings.HasPrefix(urlString, "http") {
				urlString = "https://" + urlString
			}
			u, err := url.Parse(urlString)
			if err != nil {
				//log.Fatal(err)
				logs = append(logs, fmt.Sprintf("Error: %v", errors.Unwrap(err)))
				return logs, err
			}
			host := u.Host
			h := handshake.New(host, "")
			certs, err := h.PerformHandshake()
			//fmt.Printf("Got host [%s] from options\n", host)
			logs = append(logs, fmt.Sprintf("Got host [%s] from options", host))
			if err == nil {
				if !opts.ShortSummary {
					for _, cert := range certs {
						logs = append(logs, certinfo.LogCertInfo(cert)...)
					}
				}
				//fmt.Println(strings.Repeat("-", 92))
				//fmt.Println("Chain summary")
				logs = append(logs, strings.Repeat("-", 92))
				logs = append(logs, "Chain summary")
				logs = append(logs, certinfo.LogChainSummary(certs)...)
				/*
					for i, cert := range certs {
						certinfo.LogCertSummary(cert, i)
					}
				*/
			} else {
				//fmt.Println(fmt.Errorf("reading certificates failed: %w", err))
				//log.Fatal(err)
				logs = append(logs, fmt.Sprintf("reading certificates failed: %v", errors.Unwrap(err)))
				return logs, err
			}
		}
	}
	if len(opts.Hosts) > 0 {
		//fmt.Println("reading certificates from host(s)")
		logs = append(logs, "reading certificates from host(s)")
		for k, v := range opts.Hosts {
			if !strings.HasPrefix(k, "http") {
				k = "https://" + k
			}
			u, err := url.Parse(k)
			if err != nil {
				//log.Fatal(err)
				logs = append(logs, fmt.Sprintf("Error parsing URL: %v", errors.Unwrap(err)))
				return logs, err
			}
			host := u.Host
			h := handshake.New(host, v)
			certs, err := h.PerformHandshake()
			if err == nil {
				if !opts.ShortSummary {
					for _, cert := range certs {
						logs = append(logs, certinfo.LogCertInfo(cert)...)
					}
				}
				//fmt.Println(strings.Repeat("-", 92))
				//fmt.Println("Chain summary")
				logs = append(logs, strings.Repeat("-", 92))
				logs = append(logs, "Chain summary")
				logs = append(logs, certinfo.LogChainSummary(certs)...)
			} else {
				//fmt.Println(fmt.Errorf("reading certificates failed: %w", err))
				logs = append(logs, fmt.Sprintf("reading certificates failed: %v", errors.Unwrap(err)))
				//log.Fatal(err)
				return logs, err
			}
		}
	}
	return logs, nil
}
