package providers

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testAuthProvider(hostname string) Provider {
	p := NewAuthnProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
		updateURL(p.AuthzUrl, hostname)
	}
	return p
}

func testBackend(path string, query string, payload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path || url.RawQuery != query {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAuthnProviderDefaults(t *testing.T) {
	p := testAuthProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Authn", p.Data().ProviderName)
	assert.Equal(t, "http://localhost:45101/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "http://localhost:45101/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "http://localhost:45101/oauth/r/api/v1/user/details",
		p.Data().ProfileURL.String())
	assert.Equal(t, "user.profile", p.Data().Scope)
}

func TestAuthnProviderOverrides(t *testing.T) {
	p := NewAuthnProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v4/user"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Authn", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v4/user",
		p.Data().ProfileURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}
