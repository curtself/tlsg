package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"tlsg/internal/x509extras"
)

// CertInfo contains structured information about an X.509 certificate.
// It is suitable for both human-readable output and JSON serialization.
type CertInfo struct {
	CommonName         string          `json:"commonName"`
	SubjectDN          string          `json:"subjectDN"`
	NotBefore          time.Time       `json:"notBefore"`
	NotAfter           time.Time       `json:"notAfter"`
	Issuer             string          `json:"issuer"`
	IssuerDN           string          `json:"issuerDN"`
	SerialNumber       string          `json:"serialNumber"`
	Thumbprint         string          `json:"thumbprint"`
	Thumbprint256      string          `json:"thumbprint256"`
	IsCA               bool            `json:"isCA"`
	SelfSigned         bool            `json:"selfSigned"`
	SubjectKeyID       string          `json:"subjectKeyID"`
	AuthorityKeyID     string          `json:"authorityKeyID"`
	DNSNames           []string        `json:"dnsNames"`
	IPAddresses        []string        `json:"ipAddresses"`
	EmailAddresses     []string        `json:"emailAddresses"`
	URIs               []string        `json:"uris"`
	KeyUsage           []string        `json:"keyUsage"`
	ExtendedKeyUsage   []string        `json:"extendedKeyUsage"`
	AuthorityInfo      []AuthorityInfo `json:"authorityInfo"`
	SignatureAlgorithm string          `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string          `json:"publicKeyAlgorithm"`
	PublicKeySize      int             `json:"publicKeySize"`
}

// AuthorityInfo contains information from an Authority Information Access
// extension.
type AuthorityInfo struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
}

// GetCertInfo extracts structured information from a certificate.
func GetCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		CommonName:         cert.Subject.CommonName,
		SubjectDN:          cert.Subject.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		Issuer:             cert.Issuer.CommonName,
		IssuerDN:           cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		Thumbprint:         certFingerprintSHA1(cert),
		Thumbprint256:      certFingerprintSHA256(cert),
		IsCA:               cert.IsCA,
		SelfSigned:         isSelfSigned(cert),
		SubjectKeyID:       hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(cert.AuthorityKeyId),
		DNSNames:           append([]string(nil), cert.DNSNames...),
		KeyUsage:           keyUsageList(cert.KeyUsage),
		ExtendedKeyUsage:   extKeyUsageList(cert.ExtKeyUsage),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      publicKeySize(cert.PublicKey),
	}

	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	for _, email := range cert.EmailAddresses {
		info.EmailAddresses = append(info.EmailAddresses, email)
	}

	for _, uri := range cert.URIs {
		info.URIs = append(info.URIs, uri.String())
	}

	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.5.5.7.1.1" {
			aia, err := x509extras.ParseAIA(ext.Value)
			if err == nil {
				for _, ad := range aia {
					info.AuthorityInfo = append(info.AuthorityInfo, AuthorityInfo{
						Method: x509extras.FriendlyAccessMethod(ad.Method),
						URI:    ad.URI,
					})
				}
			}
		}
	}

	return info
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func publicKeySize(pub crypto.PublicKey) int {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	default:
		return 0
	}
}

// LogCertSummary returns a short certificate summary.
func LogCertSummary(cert *x509.Certificate, index int) string {
	return fmt.Sprintf("[%d] %s", index, cert.Subject.CommonName)
}

// LogChainSummary returns a summary of the certificates in a chain.
func LogChainSummary(chain []*x509.Certificate) []string {
	var logs []string

	for i, cert := range chain {
		logs = append(logs, LogCertSummary(cert, i))
	}

	return logs
}

// LogCertInfo prints details of the given certificate.
func LogCertInfo(cert *x509.Certificate) []string {
	var logs []string
	info := GetCertInfo(cert)

	logs = append(logs, strings.Repeat("-", 92))

	if info.CommonName != "" {
		logs = append(logs, fmt.Sprintf("Simple Name: %s", info.CommonName))
	}

	logs = append(logs, fmt.Sprintf(
		"Date: %s - %s",
		info.NotBefore.Local().Format("01/02/2006 15:04:05"),
		info.NotAfter.Local().Format("01/02/2006 15:04:05"),
	))
	logs = append(logs, fmt.Sprintf("Issuer: %s", info.Issuer))
	logs = append(logs, fmt.Sprintf("Issuer DN: %s", info.IssuerDN))
	logs = append(logs, fmt.Sprintf("Serial Number: %s", info.SerialNumber))
	logs = append(logs, fmt.Sprintf("Thumbprint: %s", info.Thumbprint))
	logs = append(logs, fmt.Sprintf("Thumbprint 256: %s", info.Thumbprint256))

	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		isCritical := ext.Critical
		extName := getFriendlyName(oid)

		if isCritical {
			extName += " (critical)"
		}

		switch oid {
		case "2.5.29.19":
			logs = append(logs, fmt.Sprintf("%s: CA=%v", extName, cert.IsCA))

		case "2.5.29.14":
			logs = append(logs, fmt.Sprintf(
				"SKID%s: %s",
				criticalSuffix(isCritical),
				hex.EncodeToString(cert.SubjectKeyId),
			))

		case "2.5.29.35":
			logs = append(logs, fmt.Sprintf(
				"AKID%s: %s",
				criticalSuffix(isCritical),
				hex.EncodeToString(cert.AuthorityKeyId),
			))

		case "2.5.29.17":
			logs = append(logs, extName)

			for _, dns := range cert.DNSNames {
				logs = append(logs, fmt.Sprintf("  DNS: %s", dns))
			}

			for _, ip := range cert.IPAddresses {
				logs = append(logs, fmt.Sprintf("  IP: %s", ip.String()))
			}

			for _, email := range cert.EmailAddresses {
				logs = append(logs, fmt.Sprintf("  Email: %s", email))
			}

			for _, uri := range cert.URIs {
				logs = append(logs, fmt.Sprintf("  URI: %s", uri.String()))
			}

		case "2.5.29.15":
			logs = append(logs, fmt.Sprintf(
				"%s: %s",
				extName,
				keyUsageString(cert.KeyUsage),
			))

		case "2.5.29.37":
			logs = append(logs, fmt.Sprintf(
				"%s: %s",
				extName,
				extKeyUsageString(cert.ExtKeyUsage),
			))

		case "1.3.6.1.5.5.7.1.1":
			aia, err := x509extras.ParseAIA(ext.Value)
			if err == nil {
				for _, ad := range aia {
					logs = append(logs, fmt.Sprintf(
						"  %s: %s",
						x509extras.FriendlyAccessMethod(ad.Method),
						ad.URI,
					))
				}
			} else {
				logs = append(logs, fmt.Sprintf(
					"%s: failed to parse (%v)",
					getFriendlyName(oid),
					err,
				))
			}
		}
	}

	logs = append(logs, "")

	return logs
}

func LogCsrInfo(csr *x509.CertificateRequest) []string {
	var logs []string

	logs = append(logs, strings.Repeat("-", 92))

	if csr.Subject.CommonName != "" {
		logs = append(logs, fmt.Sprintf(
			"Simple Name: %s",
			csr.Subject.CommonName,
		))
	}

	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		logs = append(logs, fmt.Sprintf(
			"Key Size: %d",
			pub.N.BitLen(),
		))
	case *ecdsa.PublicKey:
		logs = append(logs, fmt.Sprintf(
			"Key Size: %d (ECDSA)",
			pub.Params().BitSize,
		))
	default:
		logs = append(logs, fmt.Sprintf(
			"Key Type: %T",
			pub,
		))
	}

	for _, ext := range csr.Extensions {
		oid := ext.Id.String()
		extName := getFriendlyName(oid)

		switch oid {
		case "2.5.29.14":
			var skid []byte

			_, err := asn1.Unmarshal(ext.Value, &skid)
			if err == nil {
				logs = append(logs, fmt.Sprintf(
					"SKID: %s",
					strings.ToUpper(hex.EncodeToString(skid)),
				))
			}

		case "2.5.29.17":
			logs = append(logs, extName)

			for _, dns := range csr.DNSNames {
				logs = append(logs, fmt.Sprintf("  DNS: %s", dns))
			}

		case "2.5.29.15":
			var usage x509.KeyUsage
			var bitString asn1.BitString

			if _, err := asn1.Unmarshal(ext.Value, &bitString); err == nil {
				if bitString.BitLength >= 1 && bitString.At(0) == 1 {
					usage |= x509.KeyUsageDigitalSignature
				}
				if bitString.BitLength >= 2 && bitString.At(1) == 1 {
					usage |= x509.KeyUsageContentCommitment
				}
				if bitString.BitLength >= 3 && bitString.At(2) == 1 {
					usage |= x509.KeyUsageKeyEncipherment
				}
				if bitString.BitLength >= 4 && bitString.At(3) == 1 {
					usage |= x509.KeyUsageDataEncipherment
				}
				if bitString.BitLength >= 5 && bitString.At(4) == 1 {
					usage |= x509.KeyUsageKeyAgreement
				}
				if bitString.BitLength >= 6 && bitString.At(5) == 1 {
					usage |= x509.KeyUsageCertSign
				}
				if bitString.BitLength >= 7 && bitString.At(6) == 1 {
					usage |= x509.KeyUsageCRLSign
				}
				if bitString.BitLength >= 8 && bitString.At(7) == 1 {
					usage |= x509.KeyUsageEncipherOnly
				}
				if bitString.BitLength >= 9 && bitString.At(8) == 1 {
					usage |= x509.KeyUsageDecipherOnly
				}

				logs = append(logs, fmt.Sprintf(
					"%s: %s",
					extName,
					keyUsageString(usage),
				))
			} else {
				logs = append(logs, fmt.Sprintf(
					"%s: unable to parse Key Usage (%v)",
					extName,
					err,
				))
			}

		case "2.5.29.37":
			var ekuOIDs []asn1.ObjectIdentifier

			if _, err := asn1.Unmarshal(ext.Value, &ekuOIDs); err == nil {
				var ekuNames []string

				for _, oid := range ekuOIDs {
					ekuNames = append(ekuNames, friendlyExtKeyUsage(oid))
				}

				logs = append(logs, fmt.Sprintf(
					"%s: %s",
					extName,
					strings.Join(ekuNames, ", "),
				))
			} else {
				logs = append(logs, fmt.Sprintf(
					"%s: unable to parse EKU (%v)",
					extName,
					err,
				))
			}
		}
	}

	return logs
}

func ComputeSKIDFromPublicKey(pubKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	skid := sha1.Sum(pubBytes)

	return skid[:], nil
}

func friendlyExtKeyUsage(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 1}):
		return "Server Authentication"
	case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 2}):
		return "Client Authentication"
	case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 3}):
		return "Code Signing"
	case oid.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 4}):
		return "Email Protection"
	default:
		return "Unknown EKU: " + oid.String()
	}
}

// certFingerprintSHA1 returns the SHA-1 fingerprint of the complete
// DER-encoded certificate.
func certFingerprintSHA1(cert *x509.Certificate) string {
	fp := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(fp[:]))
}

// certFingerprintSHA256 returns the SHA-256 fingerprint of the
// complete DER-encoded certificate.
func certFingerprintSHA256(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(fp[:]))
}

func criticalSuffix(critical bool) string {
	if critical {
		return " (critical)"
	}

	return ""
}

func getFriendlyName(oid string) string {
	switch oid {
	case "2.5.29.19":
		return "Basic Constraints"
	case "2.5.29.14":
		return "Subject Key Identifier"
	case "2.5.29.35":
		return "Authority Key Identifier"
	case "2.5.29.17":
		return "Subject Alternative Name"
	case "2.5.29.15":
		return "Key Usage"
	case "2.5.29.37":
		return "Enhanced Key Usage"
	case "1.3.6.1.5.5.7.1.1":
		return "Authority Information Access"
	default:
		return "Unknown OID: " + oid
	}
}

func keyUsageString(ku x509.KeyUsage) string {
	return strings.Join(keyUsageList(ku), ", ")
}

func keyUsageList(ku x509.KeyUsage) []string {
	var usages []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return usages
}

func extKeyUsageString(usages []x509.ExtKeyUsage) string {
	return strings.Join(extKeyUsageList(usages), ", ")
}

func extKeyUsageList(usages []x509.ExtKeyUsage) []string {
	var result []string

	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "Time Stamping")
		default:
			result = append(result, fmt.Sprintf("Unknown (%d)", usage))
		}
	}

	return result
}
