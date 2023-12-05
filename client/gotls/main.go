package main

import (
	"crypto/x509"
	"log"
	"net"
	"os"
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

	dat, err := os.ReadFile("../../go_server/server.crt")
	if err != nil {
		log.Println(err)
		return
	}

	cert_pool := x509.NewCertPool()
	cert_pool.AppendCertsFromPEM(dat)

	config := &tls.Config{
		ServerName: "127.0.0.1",
		RootCAs:    cert_pool,
	}

	start := time.Now()
	tlsConn := tls.UClient(dialConn, config, tls.HelloCustom)
	defer tlsConn.Close()

	err = tlsConn.ApplyPreset(&tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		TLSVersMin: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	})
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatalf("tlsConn.Handshake() failed: %+v\n", err)
	}
	elapsed := time.Since(start)
	log.Printf("Handshake took %s\n", elapsed)

	log.Printf("Current ciphersuite: %s\n", tls.CipherSuiteName(tlsConn.HandshakeState.ServerHello.CipherSuite))
}
