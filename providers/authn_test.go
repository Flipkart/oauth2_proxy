package providers

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testAuthProvider(authn_hostname string, authz_hostname string) Provider {
	p := NewAuthnProvider(
		&ProviderData{})
	p.AuthzUrl = &url.URL{}
	if authn_hostname != "" {
		updateURL(p.Data().LoginURL, authn_hostname)
		updateURL(p.Data().RedeemURL, authn_hostname)
		updateURL(p.Data().ProfileURL, authn_hostname)
	}
	if authz_hostname != "" {
		updateURL(p.AuthzUrl, authz_hostname)
	}
	return p
}

func testBackend(path string, query string, auth_token string, payload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path || url.RawQuery != query || r.Header.Get("Authorization") != auth_token {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAuthnProviderDefaults(t *testing.T) {
	p := testAuthProvider("", "")
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
			ProfileURL: &url.URL{
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

func TestAuthnProvider_GetEmailAddress(t *testing.T) {
	var tests = []struct {
		name          string
		session       SessionState
		authnResponse string
		email         string
		authzResponse string
		roles         []string
		err           error
	}{
		{"validToken", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "abc.d@flipkart.com", "[\"abc\", \"def\"]", []string{"abc", "def"}, nil},
		{"invalidToken", SessionState{AccessToken: "unexpected_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "", "[\"abc\", \"def\"]", nil, errors.New("got 404 ")},
		{"invalidResponseNoEmail", SessionState{AccessToken: "imaginary_access_token"}, "{ \"sub\": \"abc.d\"}", "", "[\"abc\", \"def\"]", nil, errors.New("type assertion to string failed")},
		{"invalidResponseNoSub", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\"}", "", "[\"abc\", \"def\"]", nil, errors.New("type assertion to string failed")},
		{"validTokenInvalidAuthzRoles", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "abc.d@flipkart.com", "{\"abc\": \"def\"}", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authnBackend := testBackend("/oauth/r/api/v1/user/details", "", "Bearer imaginary_access_token", tc.authnResponse)
			authzBackend := testBackend("/roles", "user_id=abc.d", "", tc.authzResponse)
			defer authnBackend.Close()
			defer authzBackend.Close()

			authn_url, _ := url.Parse(authnBackend.URL)
			authz_url, _ := url.Parse(authzBackend.URL)
			p := testAuthProvider(authn_url.Host, authz_url.Host)

			session := &tc.session
			email, err := p.GetEmailAddress(session)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.email, email)
			assert.Equal(t, tc.roles, session.Roles)
		})
	}
}

func TestAuthnProvider_GetUserName(t *testing.T) {
	var tests = []struct {
		name          string
		session       SessionState
		authnResponse string
		user          string
		authzResponse string
		roles         []string
		err           error
	}{
		{"validToken", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "abc.d", "[\"abc\", \"def\"]", []string{"abc", "def"}, nil},
		{"invalidToken", SessionState{AccessToken: "unexpected_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "", "[\"abc\", \"def\"]", nil, errors.New("got 404 ")},
		{"invalidResponseNoEmail", SessionState{AccessToken: "imaginary_access_token"}, "{ \"sub\": \"abc.d\"}", "", "[\"abc\", \"def\"]", nil, errors.New("type assertion to string failed")},
		{"invalidResponseNoSub", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\"}", "", "[\"abc\", \"def\"]", nil, errors.New("type assertion to string failed")},
		{"validTokenInvalidAuthzRoles", SessionState{AccessToken: "imaginary_access_token"}, "{\"email\": \"abc.d@flipkart.com\", \"sub\": \"abc.d\"}", "abc.d", "{\"abc\": \"def\"}", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authnBackend := testBackend("/oauth/r/api/v1/user/details", "", "Bearer imaginary_access_token", tc.authnResponse)
			authzBackend := testBackend("/roles", "user_id=abc.d", "", tc.authzResponse)
			defer authnBackend.Close()
			defer authzBackend.Close()

			authn_url, _ := url.Parse(authnBackend.URL)
			authz_url, _ := url.Parse(authzBackend.URL)
			p := testAuthProvider(authn_url.Host, authz_url.Host)

			session := &tc.session
			email, err := p.GetUserName(session)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.user, email)
			assert.Equal(t, tc.roles, session.Roles)
		})
	}
}
