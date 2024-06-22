package hsdpsigner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	signer "github.com/philips-software/go-hsdp-signer"
	"github.com/stretchr/testify/assert"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type nilHandler struct {
}

func (n *nilHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("X-Client-Common-Name", r.Header.Get("X-Client-Common-Name"))
	w.Header().Set("X-Client-Certificate-Der-Base64", r.Header.Get("X-Client-Certificate-Der-Base64"))
	return nil
}

func TestMiddleware_CaddyModule(t *testing.T) {
	var err error
	m := new(Middleware)

	m.SharedKey = "shared_key"
	m.SecretKey = "secret_key"
	m.s, err = signer.New(m.SharedKey, m.SecretKey,
		signer.SignHeaders("X-Client-Common-Name", "X-Client-Certificate-Der-Base64"))
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	cm := m.CaddyModule()

	if cm.ID != "http.handlers.hsdpsigner" {
		t.Errorf("Unexpected ID: %s", m.CaddyModule().ID)
	}

	// Create a new TLS test server with the echo handler
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = m.ServeHTTP(w, r, &nilHandler{})
	}))
	ts.TLS.ClientAuth = tls.RequestClientCert

	defer ts.Close()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to private key: %v", err)
	}

	// Create a certificate template
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test Common Name",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	// Construct the tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes}, // Certificate chain
		PrivateKey:  privateKey,
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ts.Certificate())

	// Create a client that accepts any certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &tlsCert, nil
				},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			},
		},
	}

	// Make a request to the test server
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, "Test Common Name", resp.Header.Get("X-Client-Common-Name"))
	assert.NotEqual(t, "", resp.Header.Get("X-Client-Certificate-Der-Base64"))

	// Read the response body
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
}
