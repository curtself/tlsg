package certformat

import (
	//"bufio"
	"os"
)

// Format represents the type of certificate encoding.
type Format int

const (
	Unknown Format = iota
	PEM
	DER
)

// CertificateFormat is a namespace-like value to access detection logic.
var CertificateFormat formatDetector

type formatDetector struct{}

// Detect reads the given file path and tries to determine if it's DER or PEM.
func (formatDetector) Detect(path string) Format {
	bytes, err := getFileBytes(path)
	if err != nil {
		return Unknown
	}
	isBinary, err := isBinaryData(bytes)
	if err != nil {
		return Unknown
	}
	if isBinary {
		return DER
	}
	return PEM
}

// DetectBytes reads the bytes to determine if it's DER or PEM
// It's really a public wrapper for "isBinaryData([]byte)"
func (formatDetector) DetectBytes(bytes []byte) Format {
	isBinary, err := isBinaryData(bytes)
	if err != nil {
		return Unknown
	}
	if isBinary {
		return DER
	}
	return PEM
}

// just get bytes from a file
func getFileBytes(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func isBinaryData(bytes []byte) (bool, error) {
	for i := range bytes {
		b := bytes[i]
		if (b > 0 && b < 8) || (b > 13 && b < 26) {
			return true, nil
		}
	}
	return false, nil
}
