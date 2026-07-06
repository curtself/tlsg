package x509extras

import (
	//"crypto/x509/pkix"
	"encoding/asn1"
	//"errors"
)

var (
	OIDAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDAccessMethodOCSP      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	OIDAccessMethodCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// knownAccessMethods maps known AIA access method OIDs to their friendly names.
var knownAccessMethods = map[string]string{
	OIDAccessMethodOCSP.String():      "OCSP",
	OIDAccessMethodCAIssuers.String(): "CA Issuers",
}

type accessDescriptionRaw struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// AccessDescription mirrors RFC 5280
type AccessDescription struct {
	Method asn1.ObjectIdentifier
	URI    string
}

// AuthorityInfoAccessSyntax as defined in RFC 5280
type AuthorityInfoAccessSyntax []AccessDescription

func ParseAIA(der []byte) (AuthorityInfoAccessSyntax, error) {
	var rawSeq []accessDescriptionRaw
	_, err := asn1.Unmarshal(der, &rawSeq)
	if err != nil {
		return nil, err
	}

	var aia AuthorityInfoAccessSyntax
	for _, raw := range rawSeq {
		// Only support uniformResourceIdentifier (tag [6], context-specific)
		if raw.Location.Class == 2 && raw.Location.Tag == 6 {
			aia = append(aia, AccessDescription{
				Method: raw.Method,
				URI:    string(raw.Location.Bytes),
			})
		}
	}
	return aia, nil
}

// FriendlyAccessMethod returns a human-readable name for a known AIA access method OID.
func FriendlyAccessMethod(oid asn1.ObjectIdentifier) string {
	if name, ok := knownAccessMethods[oid.String()]; ok {
		return name
	}
	return "Unknown OID (" + oid.String() + ")"
}
