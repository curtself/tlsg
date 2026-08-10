package handshake

import (
	"crypto/x509"
	"errors"
	//"fmt"
	//"os"
)

type CheckVariantOptions struct {
	ForceVariant bool
}
type CheckVariantOption func(*CheckVariantOptions)

func WithForceVariant() CheckVariantOption {
	return func(o *CheckVariantOptions) {
		o.ForceVariant = true
	}
}

func CheckVariant(data []byte, opts ...CheckVariantOption) VariantInfo {
	options := CheckVariantOptions{
		ForceVariant: false, // default
	}

	for _, opt := range opts {
		opt(&options)
	}

	return checkVariantInternal(data, options)
}

// VariantInfo represents the detected variant of the TLS handshake
type VariantInfo struct {
	VariantType string
	Index       int
}

// indexOf returns the first index of val in data starting from fromIdx, or -1 if not found
func indexOf(data []byte, val byte, fromIdx int) int {
	for i := fromIdx; i < len(data); i++ {
		if data[i] == val {
			return i
		}
	}
	return -1
}

// CheckVariant scans the data for known TLS 1.2 ServerHello certificate message variants
func checkVariantInternal(data []byte, options CheckVariantOptions) VariantInfo {
	// standard_tls12 detection
	headMarker := indexOf(data, 0x16, 1) // skip first byte
	headParseAttempts := 0

	if ! options.ForceVariant {
		for headMarker != -1 {
			if headParseAttempts > 60 || headMarker+5 >= len(data) {
				break
			}
			if data[headMarker+5] == 0x0B {
				return VariantInfo{"standard_tls12", headMarker}
			}
			headMarker = indexOf(data, 0x16, headMarker+1)
			headParseAttempts++
		}
	}

	// variant_tls12 detection
	certMarker := indexOf(data, 0x0B, 0)
	certParseAttempts := 0

	for certMarker != -1 {
		if certParseAttempts > 40 || certMarker+7 >= len(data) {
			break
		}
		if certMarker-5 > 0 && certMarker+3 < len(data) {
			certsLength := int(data[certMarker+1])<<16 | int(data[certMarker+2])<<8 | int(data[certMarker+3])
			if certsLength < len(data) && data[certMarker+1] == 0x00 {
				return VariantInfo{"variant_tls12", certMarker}
			}
		}
		certMarker = indexOf(data, 0x0B, certMarker+1)
		certParseAttempts++
	}

	return VariantInfo{"unknown", -1}
}

// ParseCertificates extracts the certificate chain from TLS 1.2 handshake response bytes
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	variant := CheckVariant(data)

	certs, err := parseCertificatesWithVariant(data, variant)
	if err != nil {
		return nil, err
	}

	// If standard parse failed, retry as forced variant
	if variant.VariantType == "standard_tls12" && len(certs) == 0 {
		variant = CheckVariant(data, WithForceVariant())
		certs, err = parseCertificatesWithVariant(data, variant)
		if err != nil {
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates parsed")
	}
	return certs, nil
}

func parseCertificatesWithVariant(data []byte, variant VariantInfo) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var index int
	var certDataLen int

	//fmt.Printf("Parsing certificates from a %s response...\n", variant.VariantType)

	switch variant.VariantType {
	case "standard_tls12":
		index = variant.Index
		if index+11 >= len(data) {
			return nil, errors.New("not enough data for standard_tls12 cert length")
		}
		certDataLen = int(data[index+9])<<16 | int(data[index+10])<<8 | int(data[index+11])
		index += 12

	case "variant_tls12":
		index = variant.Index
		if index+6 >= len(data) {
			return nil, errors.New("not enough data for variant_tls12 cert length")
		}
		certDataLen = int(data[index+4])<<16 | int(data[index+5])<<8 | int(data[index+6])
		index += 7

	default:
		/*
		// Save the raw data to a file for debugging
		err := os.WriteFile("server_hello_dump.bin", data, 0644)
		if err != nil {
			fmt.Printf("Failed to save unknown TLS variant to file: %v\n", err)
		} else {
			fmt.Printf("Saved unknown TLS response to server_hello_dump.bin (%d bytes)\n", len(data))
		}
		*/
		return nil, errors.New("unknown TLS variant; no certs parsed")
	}

	for certDataLen > 0 && index+3 < len(data) {
		certLen := int(data[index])<<16 | int(data[index+1])<<8 | int(data[index+2])
		index += 3
		if index+certLen > len(data) {
			break
		}

		certBytes := data[index : index+certLen]
		index += certLen
		certDataLen -= certLen + 3

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			//fmt.Printf("Warning: failed to parse cert at offset %d: %v\n", index, err)
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

