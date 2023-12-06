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

func time_one_handshake(ip string, c uint16, cp x509.CertPool) time.Duration {
	config := &tls.Config{
		ServerName:   ip,
		RootCAs:      &cp,
		CipherSuites: []uint16{c},
	}

	start := time.Now()
	dialConn, err := net.Dial("tcp", ip+":443")
	if err != nil {
		log.Fatalf("net.Dial() failed: %+v\n", err)
	}
	defer dialConn.Close()
	tlsConn := tls.UClient(dialConn, config, tls.HelloCustom)
	defer tlsConn.Close()

	if err != nil {
		log.Fatalf("tlsConn.Handshake() failed: %+v\n", err)
	}
	return time.Since(start)
}

func time_handshake(ip string, c uint16, cp x509.CertPool, count uint64) time.Duration {
	duration := time.Duration(0)

	for i := uint64(0); i < count; i++ {
		duration += time_one_handshake(ip, c, cp)
		time.Sleep(1 * time.Millisecond)
	}

	return time.Duration(uint64(duration) / count)
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalln("not enough args: <ip> <cert> <iter>")
	}

	ip := os.Args[1]
	dat, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Println(err)
		return
	}

	cert_pool := x509.NewCertPool()
	cert_pool.AppendCertsFromPEM(dat)

	count, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		log.Println(err)
		return
	}

	for _, c := range []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	} {
		log.Printf("Ciphersuite: %s\n", tls.CipherSuiteName(c))
		log.Printf("Handshake took %s\n", time_handshake(ip, c, *cert_pool, count))
	}
}
