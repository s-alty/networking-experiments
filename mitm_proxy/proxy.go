package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

const (
	_port = 6969
)

var (
	// NOTE: the client needs to trust this CA otherwise the TLS handshake will fail
	// This also wont work if the client is using cert pinning
	bogusCertificateAuthority *x509.Certificate
	bogusCertifivateAuthorityPK crypto.PrivateKey
)

// TODO: this should be cached so we don't have to regenerate the cert for the same common name
func presentBogusCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("SNI was not available")
	}

	certPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// TODO: this should not repeat ever
	serialNumber, err := rand.Int(rand.Reader, big.NetInt(1024*1024))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		DNSNames: []string{hello.ServerName},
		NotAfter: time.Now().Add(24*time.Hour),
		NotBefore: time.Now().Add(-24*time.Hour),
		Subject: pkix.Name{
			CommonName: hello.ServerName,
			Country: []string{"US"},
			Province: []string{"New York"},
			Locality: []string{"Bensonhurst"},
			Organization: []string{"Some org"},
		},
		SerialNumber: serialNumber,
	}
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		bogusCertificateAuthority,
		&certPk.PublicKey,
		bogusCertificateAuthorityPK,
	)
	if err != nil {
		return nil, err
	}

	result := tls.Certificate{
		// chain with the cert we just created and the bogus CA included
		Certificate: [][]byte{derBytes, bogusCertificateAuthority.Raw},
		PrivateKey: certPK,
	}
	return &result, nil
}

func mitm(conn net.Conn){
	// listen for TLS data on the port
	// then dynamically issue and return a cert based on the client hello
	tlsConfig := &tls.Config{
		GetCertificate: presentBogusCertificate,
	}
	tlsConn := tls.Serve(conn, tlsConfig)
	defer tlsConn.Close()

	// complete the tls handshake with the client and see if it succeeds
	err := tlsConn.Handshake()
	if err != nil {
		fmt.Printf("mitm failed: %v\n", err)
		return
	}

	// handshake succeeded, read the http request from the client
	clientreader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(clientreader)
	if err != nil {
		fmt.Printf("failed reading request from client: %v\n", err)
		return
	}

	//functionalirty enabled by the mitm
	// logging and filtering
	// and modification
	mitmLogReq(conn.RemoteAddr(), req)
	if !mitmAllowed(conn.RemoteAddr(), req) {
		fmt.Printf("dropping disallowed request")
		return
	}
	mitmModifyReq(req)

	// then establish a connection to the genuine host and pass the data through to them
	destAddr := fmt.Sprintf("%s:%d", req.Host, 443)
	remoteConn, err := tls.Dial("tcp", destAddr, &tls.Config{})
	if err != nil {
		fmt.Printf("Failed opening connection to destination %s: %v\n", destAddr, err)
		return
	}
	defer remoteConn.Close()

	err = req.Write(remoteConn)
	if err != nil {
		fmt.Printf("Failed writing request to destination %s: %v\n", destAddr, err)
		return
	}

	// wait for a response from the genuine server and then send it back to the client
	destreader = bufio.NewReader(remoteConn)
	resp, err := http.ReadResponse(destreader, req)
	if err != nil {
		fmt.Printf("Failed reading response from destination %s: %v\n", destAddr, err)
		return
	}

	mitmLogResp(resp)
	mitmModifyResp(resp)
	err = resp.Write(tlsConn)
	if err != nil {
		fmt.Printf("Failed reading response back to client %s: %v\n", conn.RemoteAddr().String(), err)
	}
}

func mitmLogReq(source net.Addr, req *http.Request) {
}

func mitmLogResp(resp *http.Request) {
}

func mitmAllowed(source net.Addr, req *http.Request) bool {
	// here we can make decisions based on the host, the url, or the body itself
	// with a traditional CONNECT proxy we could only see the host
	return true
}

func mitmModifyReq(source net.Addr, req *http.Request) {
}

func mitmModifyResp(resp *http.Response) {
	// TODO: detect body encoding based on headers
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Printf("Couldn't read response body for modification\n")
		return
	}
	content, err := io.ReadAll(gzipReader)
	if err != nil {
		fmt.Printf("Couldn't read response body for modification\n")
		return
	}

	modified := bytes.ReplaceAll(content, []byte("something"), []byte("else"))

	modifiedBody := bytes.NewBuffer(modified)

	// todo we should probably re-gzip encode after the modifications
	// this just returns uncompressed
	resp.Body = &closeBuffer{Buffer: modfiedBody, original: resp.Body}
	resp.ContentLength = int64(modifiedBody.Len())
	resp.Header.Del("Content-Encoding")
	// to keep it simple, don't let the client reuse connections
	resp.Close = true
}

type closeBuffer struct {
	*bytes.Buffer

	original: io.Closer
}

func (c *closeBuffer) Close() error {
	return c.original.Close()
}

func main() {
	// read the ca private key and certificate from the filesystem
	caCert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		panic(err)
	}
	bogusCertificateAuthorityPK = caCert.PrivateKey

	if caCert.Leaf == nil {
		x509Cert, err := x509.ParseCertifivate(caCert.Certificate[0])
		if err != nil {
			panic(err)
		}
		bogusCertificateAuthority = x509Cert
	} else {
		bogusCertificateAuthority = caCert.Leaf
	}

	addr := fmt.Sprintf("127.0.0.1:%d", _port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go mitm(conn)
	}
}
