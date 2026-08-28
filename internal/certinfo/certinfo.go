package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	//"log"
	"strings"
	"tlsg/internal/x509extras"
)

func LogCertSummary(cert *x509.Certificate, index int) string {
	//log.SetFlags(0)
	//log.Printf("[%d] %s", index, cert.Subject.CommonName)
	return fmt.Sprintf("[%d] %s", index, cert.Subject.CommonName)
}

func LogChainSummary(chain []*x509.Certificate) []string {
	//log.SetFlags(0)
	var logs []string
	for i, cert := range chain {
		logs = append(logs, LogCertSummary(cert, i))
	}
	return logs
}

// LogCertInfo prints details of the given certificate
func LogCertInfo(cert *x509.Certificate) []string {
	//log.SetFlags(0)
	var logs []string
	//log.Println(strings.Repeat("-", 92))
	logs = append(logs, strings.Repeat("-", 92))
	if cert.Subject.CommonName != "" {
		//log.Printf("Simple Name: %s", cert.Subject.CommonName)
		logs = append(logs, fmt.Sprintf("Simple Name: %s", cert.Subject.CommonName))
	}
	logs = append(logs, fmt.Sprintf("Date: %s - %s", cert.NotBefore.Local().Format("01/02/2006 15:04:05"), cert.NotAfter.Local().Format("01/02/2006 15:04:05")))
	logs = append(logs, fmt.Sprintf("Issuer: %s", cert.Issuer.CommonName))
	logs = append(logs, fmt.Sprintf("Issuer DN: %s", cert.Issuer.String()))
	logs = append(logs, fmt.Sprintf("Serial Number: %s", cert.SerialNumber.String()))
	logs = append(logs, fmt.Sprintf("Thumbprint: %X", certFingerprintSHA1(cert)))
	//log.Printf("Date: %s - %s", cert.NotBefore.Local().Format("01/02/2006 15:04:05"), cert.NotAfter.Local().Format("01/02/2006 15:04:05"))
	//log.Printf("Issuer: %s", cert.Issuer.CommonName)
	//log.Printf("Issuer DN: %s", cert.Issuer.String())
	//log.Printf("Serial Number: %s", cert.SerialNumber.String())
	//log.Printf("Thumbprint: %X", certFingerprintSHA1(cert))

	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		isCritical := ext.Critical
		extName := getFriendlyName(oid)
		if isCritical {
			extName += " (critical)"
		}

		switch oid {
		case "2.5.29.19": // Basic Constraints
			//log.Printf("%s: CA=%v", extName, cert.IsCA)
			logs = append(logs, fmt.Sprintf("%s: CA=%v", extName, cert.IsCA))

		case "2.5.29.14": // Subject Key Identifier
			//log.Printf("SKID%s: %s", criticalSuffix(isCritical), hex.EncodeToString(cert.SubjectKeyId))
			logs = append(logs, fmt.Sprintf("SKID%s: %s", criticalSuffix(isCritical), hex.EncodeToString(cert.SubjectKeyId)))

		case "2.5.29.35": // Authority Key Identifier
			//log.Printf("AKID%s: %s", criticalSuffix(isCritical), hex.EncodeToString(cert.AuthorityKeyId))
			logs = append(logs, fmt.Sprintf("AKID%s: %s", criticalSuffix(isCritical), hex.EncodeToString(cert.AuthorityKeyId)))

		case "2.5.29.17": // Subject Alternative Name
			//log.Printf("%s", extName)
			logs = append(logs, fmt.Sprintf("%s", extName))
			for _, dns := range cert.DNSNames {
				//log.Printf("  DNS: %s", dns)
				logs = append(logs, fmt.Sprintf("  DNS: %s", dns))
			}

		case "2.5.29.15": // Key Usage
			//log.Printf("%s: %s", extName, keyUsageString(cert.KeyUsage))
			logs = append(logs, fmt.Sprintf("%s: %s", extName, keyUsageString(cert.KeyUsage)))

		case "2.5.29.37": // Extended Key Usage
			//log.Printf("%s: %s", extName, extKeyUsageString(cert.ExtKeyUsage))
			logs = append(logs, fmt.Sprintf("%s: %s", extName, extKeyUsageString(cert.ExtKeyUsage)))

		case "1.3.6.1.5.5.7.1.1": // AIA
			aia, err := x509extras.ParseAIA(ext.Value)
			if err == nil {
				//log.Printf("%s", getFriendlyName(oid)) // still works
				//logs = append(logs, fmt.Sprintf("%s", getFriendlyName(oid)))
				for _, ad := range aia {
					//log.Printf("  %s: %s", x509extras.FriendlyAccessMethod(ad.Method), ad.URI)
					logs = append(logs, fmt.Sprintf("  %s: %s", x509extras.FriendlyAccessMethod(ad.Method), ad.URI))

				}
			} else {
				//log.Printf("%s: failed to parse (%v)", getFriendlyName(oid), err)
				logs = append(logs, fmt.Sprintf("%s: failed to parse (%v)", getFriendlyName(oid), err))

			}
		}
	}

	//log.Println()
	logs = append(logs, "")
	return logs
}

func LogCsrInfo(csr *x509.CertificateRequest) []string {
	var logs []string
	//log.SetFlags(0)
	//log.Println(strings.Repeat("-", 92))
	logs = append(logs, strings.Repeat("-", 92))
	if csr.Subject.CommonName != "" {
		//log.Printf("Simple Name: %s", csr.Subject.CommonName)
		logs = append(logs, fmt.Sprintf("Simple Name: %s", csr.Subject.CommonName))
	}

	// Key Size
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		//log.Printf("Key Size: %d", pub.N.BitLen())
		logs = append(logs, fmt.Sprintf("Key Size: %d", pub.N.BitLen()))
	case *ecdsa.PublicKey:
		//log.Printf("Key Size: %d (ECDSA)", pub.Params().BitSize)
		logs = append(logs, fmt.Sprintf("Key Size: %d (ECDSA)", pub.Params().BitSize))
	default:
		//log.Printf("Key Type: %T", pub)
		logs = append(logs, fmt.Sprintf("Key Type: %T", pub))
	}
	// Parse Extensions
	for _, ext := range csr.Extensions {
		oid := ext.Id.String()
		extName := getFriendlyName(oid)

		switch oid {
		case "2.5.29.14": // SKID
			var skid []byte
			_, err := asn1.Unmarshal(ext.Value, &skid)
			if err == nil {
				//log.Printf("SKID: %s", strings.ToUpper(hex.EncodeToString(skid)))
				logs = append(logs, fmt.Sprintf("SKID: %s", strings.ToUpper(hex.EncodeToString(skid))))
			}
			//log.Printf("SKID%s: %s", criticalSuffix(isCritical), hex.EncodeToString(ext.Value))

		case "2.5.29.17": // SAN
			//log.Printf("%s", extName)
			logs = append(logs, fmt.Sprintf("%s", extName))
			for _, dns := range csr.DNSNames {
				//log.Printf("  DNS: %s", dns)
				logs = append(logs, fmt.Sprintf("  DNS: %s", dns))
			}

		case "2.5.29.15": // Key Usage
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
				//log.Printf("%s: %s", extName, keyUsageString(usage))
				logs = append(logs, fmt.Sprintf("%s: %s", extName, keyUsageString(usage)))
			} else {
				//log.Printf("%s: unable to parse Key Usage (%v)", extName, err)
				logs = append(logs, fmt.Sprintf("%s: unable to parse Key Usage (%v)", extName, err))
			}

		case "2.5.29.37": // Extended Key Usage
			var ekuOIDs []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &ekuOIDs); err == nil {
				// Convert OIDs to ExtKeyUsage constants
				var ekuNames []string
				for _, oid := range ekuOIDs {
					ekuNames = append(ekuNames, friendlyExtKeyUsage(oid))
				}
				//log.Printf("%s: %s", extName, strings.Join(ekuNames, ", "))
				logs = append(logs, fmt.Sprintf("%s: %s", extName, strings.Join(ekuNames, ", ")))
			} else {
				//log.Printf("%s: unable to parse EKU (%v)", extName, err)
				logs = append(logs, fmt.Sprintf("%s: unable to parse EKU (%v)", extName, err))
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

/*
This version is what gets used by LogCsrInfo. x509.CertificateRequest does not
expose the KeyUsage type like x509.Certificate does so we have to parse from ASN1 data
*/
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

func certFingerprintSHA1(cert *x509.Certificate) []byte {
	fp := cert.Signature
	if len(fp) > 20 {
		fp = fp[:20]
	}
	return fp
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
	return strings.Join(usages, ", ")
}

func extKeyUsageString(usages []x509.ExtKeyUsage) string {
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
	return strings.Join(result, ", ")
}
