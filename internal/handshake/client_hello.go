package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"
)

func BuildClientHello(host string) []byte {
	recordType := &bytes.Buffer{}
	recordType.WriteByte(0x16)
	protocolVersion := &bytes.Buffer{}
	protocolVersion.Write([]byte{0x03, 0x03})
	handshakeType := &bytes.Buffer{}
	handshakeType.Write([]byte{0x01, 0x00})
	handshakeLengthPlaceholder := &bytes.Buffer{}
	handshakeLengthPlaceholder.Write([]byte{0x00, 0x00}) // write zeros for now, need to update later
	clientProtocolVersion := &bytes.Buffer{}
	clientProtocolVersion.Write([]byte{0x03, 0x03}) // tls version 1.2
	// write unix time + 28 random bytes
	randomHeader := &bytes.Buffer{}
	binary.Write(randomHeader, binary.BigEndian, uint32(time.Now().Unix()))
	random := make([]byte, 28)
	rand.Read(random)
	randomHeader.Write(random)
	sessionIdLength := &bytes.Buffer{}
	sessionIdLength.WriteByte(0x00)
	cipherSuites := &bytes.Buffer{}
	cipherSuites.Write([]byte{0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc,
		0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
		0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0,
		0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f,
		0x00, 0xff,
	})
	cipherSuitesLength := &bytes.Buffer{}
	cipherSuitesLength.Write([]byte{
		byte(len(cipherSuites.Bytes()) >> 8),
		byte(len(cipherSuites.Bytes()))})
	compressionMethods := &bytes.Buffer{}
	compressionMethods.WriteByte(0x00)
	compressionMethodsLength := &bytes.Buffer{}
	compressionMethodsLength.WriteByte(byte(len(compressionMethods.Bytes())))
	sniExt := &bytes.Buffer{}
	sniExt.Write([]byte{0x00, 0x00})                                  // extension type (SNI)
	sniExt.Write([]byte{0x00, byte(len(host) + 5)})                   // Extension length
	sniExt.Write([]byte{0x00, byte(len(host) + 3)})                   // Server Name length
	sniExt.Write([]byte{0x00, byte(len(host) >> 8), byte(len(host))}) // server name type (host_name) + host name length
	sniExt.WriteString(host)
	// add the specific extensions for this crafter clientHello message
	extensions := &bytes.Buffer{}
	extensions.Write([]byte{
		0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, // ec_point_formats
		0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, // supported_groups (only TLS 1.2 groups)
		0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
		0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
		0x01, 0x04, 0x00, 0x23, 0x00, 0x00, // session_ticket
		0x00, 0x16, 0x00, 0x00, // application_layer_protocol_negotiation
		0x00, 0x17, 0x00, 0x00, // status_request
		0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e,
		0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x1a,
		0x08, 0x1b, 0x08, 0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
		0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03,
		0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
	})
	extensionsLength := &bytes.Buffer{}
	extensionsLength.Write([]byte{
		byte((len(extensions.Bytes()) + len(sniExt.Bytes())) >> 8),
		byte(len(extensions.Bytes()) + len(sniExt.Bytes())),
	})
	// we have everything we need now, just put it together
	clientHelloMessage := &bytes.Buffer{}
	clientHelloMessage.Write(handshakeType.Bytes())
	clientHelloMessage.Write(handshakeLengthPlaceholder.Bytes())
	clientHelloMessage.Write(clientProtocolVersion.Bytes())
	clientHelloMessage.Write(randomHeader.Bytes())
	clientHelloMessage.Write(sessionIdLength.Bytes())
	clientHelloMessage.Write(cipherSuitesLength.Bytes())
	clientHelloMessage.Write(cipherSuites.Bytes())
	clientHelloMessage.Write(compressionMethodsLength.Bytes())
	clientHelloMessage.Write(compressionMethods.Bytes())
	clientHelloMessage.Write(extensionsLength.Bytes())
	clientHelloMessage.Write(sniExt.Bytes())
	clientHelloMessage.Write(extensions.Bytes())
	// get handshake length
	handshakeLength := len(clientHelloMessage.Bytes()) - 4
	// grab the bytes from the buffer and update the placeholder
	clientHelloMessageBytes := clientHelloMessage.Bytes()
	clientHelloMessageBytes[len(handshakeType.Bytes())+0] = byte(handshakeLength >> 8)
	clientHelloMessageBytes[len(handshakeType.Bytes())+1] = byte(handshakeLength)
	// get message total length
	messageLength := len(clientHelloMessageBytes)
	lengthPlaceholder := &bytes.Buffer{}
	lengthPlaceholder.Write([]byte{
		byte(messageLength >> 8), byte(messageLength),
	})
	// debug stuff
	/*
		fmt.Println("Totals")
		fmt.Printf("Handshake length: %d\n", handshakeLength)
		fmt.Printf("  As bytes: %d %d\n", byte(handshakeLength>>8), byte(handshakeLength))
		fmt.Printf("Message length: %d\n", messageLength)
		fmt.Printf("  As bytes: %d %d\n", byte(messageLength>>8), byte(messageLength))
		fmt.Printf("Start position of length: %d\n", len(recordType.Bytes())+len(protocolVersion.Bytes()))
		fmt.Printf("Start position of handshake length: %d\n", len(recordType.Bytes())+len(protocolVersion.Bytes())+len(handshakeType.Bytes()))
	*/
	// make the packet that includes all of the handshake
	packet := &bytes.Buffer{}
	packet.Write(recordType.Bytes())
	packet.Write(protocolVersion.Bytes())
	packet.Write(lengthPlaceholder.Bytes())
	packet.Write(clientHelloMessageBytes)
	// write the hello to file for inspection
	/*
		err := os.WriteFile("client_hello_dump.bin", packet.Bytes(), 0644)
		if err != nil {
			fmt.Printf("Failed to save unknown TLS variant to file: %v\n", err)
		} else {
			fmt.Printf("Saved hello packet to client_hello_dump.bin (%d bytes)\n", len(packet.Bytes()))
		}
	*/
	return packet.Bytes()
}
