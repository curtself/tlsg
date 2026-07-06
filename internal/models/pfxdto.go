package models

type PFXdto struct {
	FileName        string
	CommonName      string
	CertificateData []byte
	CreateMessage   string
	OpCode          int
}
