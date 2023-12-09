package main

import (
	"crypto/x509"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	tls "github.com/refraction-networking/utls"
)

func time_handshake(ip string, c uint16, cp *x509.CertPool, round int64, version uint16) time.Duration {
	duration := time.Duration(0)

	for i := int64(0); i < round; i++ {
		dialConn, err := net.Dial("tcp", ip+":443")
		if err != nil {
			log.Fatalf("net.Dial() failed: %+v\n", err)
		}

		tlsConn := tls.UClient(
			dialConn,
			&tls.Config{
				ServerName: ip,
				RootCAs:    cp,
				ClientAuth: tls.NoClientCert,
			},
			tls.HelloCustom,
		)

		if version == tls.VersionTLS13 {
			err = tlsConn.ApplyPreset(&tls.ClientHelloSpec{
				TLSVersMax:   version,
				TLSVersMin:   version,
				CipherSuites: []uint16{c},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"myFancyProtocol", "http/1.1"}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1}},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{1}}, // pskModeDHE
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10}},
				},
				GetSessionID: nil,
			})
		} else {
			err = tlsConn.ApplyPreset(&tls.ClientHelloSpec{
				TLSVersMax:   version,
				TLSVersMin:   version,
				CipherSuites: []uint16{c},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"myFancyProtocol", "http/1.1"}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1}},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{1}}, // pskModeDHE
				},
				GetSessionID: nil,
			})
		}

		start := time.Now()
		err = tlsConn.Handshake()
		duration += time.Since(start)

		// log.Printf("%s", duration)
		dialConn.Close()
		tlsConn.Close()

		if err != nil {
			log.Fatalf("tlsConn.Handshake() failed: %+v\n", err)
		}
	}

	return time.Duration(int64(duration) / round)
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalln("not enough args: <ip> <cert> <iter>")
	}

	ip := os.Args[1]

	dat, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Printf("Read file failed: %T", err)
		return
	}

	cert_pool := x509.NewCertPool()
	cert_pool.AppendCertsFromPEM(dat)

	rounds, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil {
		log.Printf("Read int failed: %T", err)
		return
	}

	for _, c := range []uint16{
		// TLS 1.3
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	} {
		log.Printf("Ciphersuite: %s\n", tls.CipherSuiteName(c))
		log.Printf("Handshake took %s\n", time_handshake(ip, c, cert_pool, rounds, tls.VersionTLS13))
	}
	for _, c := range []uint16{
		// TLS 1.2
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	} {
		log.Printf("Ciphersuite: %s\n", tls.CipherSuiteName(c))
		log.Printf("Handshake took %s\n", time_handshake(ip, c, cert_pool, rounds, tls.VersionTLS12))
	}
}
