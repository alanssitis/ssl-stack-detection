package main

import (
	"log"
	"net"
	"time"

	tls "github.com/refraction-networking/utls"
)

func prependRecordHeader(hello []byte, minTLSVersion uint16) []byte {
	l := len(hello)
	if minTLSVersion == 0 {
		minTLSVersion = tls.VersionTLS10
	}
	header := []byte{
		uint8(22),
		uint8(minTLSVersion >> 8 & 0xff), uint8(minTLSVersion & 0xff),
		uint8(l >> 8 & 0xff), uint8(l & 0xff),
	}
	return append(header, hello...)
}

func main() {
	dialConn, err := net.Dial("tcp", "127.0.0.1:443")
	if err != nil {
		log.Fatalf("net.Dial() failed: %+v\n", err)
	}
    defer dialConn.Close()

	config := tls.Config{
		InsecureSkipVerify: true,
        CipherSuites: []uint16{
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
	}
	tlsConn := tls.UClient(dialConn, &config, tls.HelloGolang)
	if tlsConn == nil {
		log.Fatalf("tls.UClient() failed: Connection is nil")
	}
    defer tlsConn.Close()

	start := time.Now()
	err = tlsConn.Handshake()
	elapsed := time.Since(start)
	if err != nil {
		log.Fatalf("tlsConn.Handshake() failed: %+v\n", err)
	}
	log.Printf("Handshake took %s\n", elapsed)

	fingerprinter := tls.Fingerprinter{}
	generatedSpec, err := fingerprinter.FingerprintClientHello(prependRecordHeader(tlsConn.HandshakeState.Hello.Raw, tlsConn.HandshakeState.Hello.Vers))
	if err != nil {
		log.Fatalf("fingerprinter.FingerprintClientHello() failed: %+v\n", err)
	}
	log.Print("Supported suites:\n")
	for _, suite := range generatedSpec.CipherSuites {
		log.Printf("    %s\n", tls.CipherSuiteName(suite))
	}
}
