package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type Bundle struct {
	Fullchain []byte
	PrivKey   []byte
	Cert      []byte
	Chain     []byte
	Haproxy   []byte
	Serial    string
}

func Decode(p12 []byte, password string) (*Bundle, error) {
	key, leaf, caCerts, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		return nil, fmt.Errorf("decode pkcs12: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	var chain bytes.Buffer
	for _, c := range caCerts {
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	var full bytes.Buffer
	full.Write(leafPEM)
	full.Write(chain.Bytes())

	var haproxy bytes.Buffer
	haproxy.Write(full.Bytes())
	haproxy.Write(keyPEM)

	return &Bundle{
		Fullchain: full.Bytes(),
		PrivKey:   keyPEM,
		Cert:      leafPEM,
		Chain:     chain.Bytes(),
		Haproxy:   haproxy.Bytes(),
		Serial:    strings.ToUpper(fmt.Sprintf("%X", leaf.SerialNumber)),
	}, nil
}
