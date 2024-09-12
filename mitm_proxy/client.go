package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

const (
	_proxyAddr = "127.0.0.1:6969"
	_caCertPath = "ca.crt"
)

func parseBlocks(pemBytes []byte) ([]*pem.Block, error) {
	block, rest := pem.Decode(pemBytes)

	// base case
	if block == nil {
		if len(pemBytes) > 0 {
			// there was non pem-encoded data present
			return []*pem.Block{}, fmt.Errorf("invalid pem data")
		}
		return []*pem.Block{}, nil
	}

	blocks, err := parseBlocks(rest)
	if err != nil {
		return blocks, err
	}
	result := []*pem.Block{block}
	result = append(result, blocks...)
	return result, nil
}

func parseChain(pemBytes []byte) ([]*x509.Certificate, error) {
	blocks, err := parseBlocks(pemBytes)
	if err != nil {
		return []*x509.Certificate{}, err
	}
	if len(blocks) == 0 {
		return []*x509.Certificate{}, fmt.Errorf("no pem data")
	}

	certs := x509.Certificate{}
	for _, b := range blocks {
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return cets, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func main() {
	// customizations necessary for mitm to work:
	// 1. customize the dialer to connect to the proxy server instead of the destination host
	// 2. update the TLS config to trust the phony CA
	caFile, err := os.Open(_caCertPath)
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(caFile)
	if err != nil {
		panic(err)
	}
	phonyCA, err := parseChain(data)
	if err != nil {
		panic(err)
	}

	phonyPool := x509.NewCertPool()
	phonyPool.AddCert(phonyCA[0])

	mitmProxyClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("tcp", _proxyAddr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: phonyPool,
			},
		},
	}

	resp, err := mitmProxyClient.Get("https://www.example.org/path")
	if err != nil {
		panic(err)
	}
	content, _ := io.ReadAll(resp.Body)
	fmt.Printf("Got response:\n\n%s\n", string(content))
}
