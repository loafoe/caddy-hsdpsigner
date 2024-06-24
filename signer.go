package hsdpsigner

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/philips-software/go-hsdp-signer"
)

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("hsdpsigner", parseCaddyfile)
}

type Middleware struct {
	SharedKey string `json:"shared_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`

	s *signer.Signer

	settings []debug.BuildSetting
	revision string
}

// CaddyModule returns the Caddy module information.
func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hsdpsigner",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	var err error

	info, ok := debug.ReadBuildInfo()
	if ok {
		m.settings = info.Settings
		for _, kv := range info.Settings {
			if kv.Key == "vcs.revision" {
				m.revision = kv.Value
			}
		}
	}
	m.s, err = signer.New(m.SharedKey, m.SecretKey,
		signer.SignHeaders("X-Client-Common-Name", "X-Client-Certificate-Der-Base64"))
	return err
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.s == nil {
		return fmt.Errorf("no signer")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	r.Header.Set("X-Caddy-Plugin-Revision", m.revision)
	// Inject TLS headers
	if r.TLS != nil && r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		r.Header.Set("X-Client-Common-Name", r.TLS.PeerCertificates[0].Subject.CommonName)
		r.Header.Set("X-Client-Certificate-Der-Base64", certToDERBase64(r.TLS.PeerCertificates[0]))
	}
	err := m.s.SignRequest(r)
	if err != nil {
		return err
	}
	return next.ServeHTTP(w, r)
}

func certToDERBase64(certificate *x509.Certificate) string {
	// Cert to DER Base64
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.SharedKey, &m.SecretKey) {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
