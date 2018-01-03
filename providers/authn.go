package providers

import (
	"fmt"
	"github.com/Flipkart/oauth2_proxy/api"
	"log"
	"net/http"
	"net/url"
)

type AuthnProvider struct {
	*ProviderData
	AuthzUrl *url.URL
}

func NewAuthnProvider(p *ProviderData) *AuthnProvider {
	p.ProviderName = "Authn"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "http",
			Host:   "localhost:45101",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "http",
			Host:   "localhost:45101",
			Path:   "/oauth/token",
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "http",
			Host:   "localhost:45101",
			Path:   "/oauth/r/api/v1/user/details",
		}
	}
	if p.Scope == "" {
		p.Scope = "user.profile"
	}
	return &AuthnProvider{ProviderData: p}
}

func (p *AuthnProvider) getDetails(s *SessionState) {
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))

	json, err := api.Request(req)

	if err != nil {
		log.Printf("failed making request %s", err)
		return
	}
	s.Email, err = json.Get("email").String()
	if err != nil {
		log.Printf("email not found")
		return
	}
	s.User, err = json.Get("sub").String()
	if err != nil {
		log.Printf("sub not found")
		return
	}
	err = p.getRolesAndPerms(s)
	if err != nil {
		log.Printf("could not obtain roles %s", err)
		return
	}
}

func (p *AuthnProvider) GetEmailAddress(s *SessionState) (string, error) {
	if s.Email == "" {
		p.getDetails(s)
	}
	return s.Email, nil
}

func (p *AuthnProvider) GetUserName(s *SessionState) (string, error) {
	if s.User == "" {
		p.getDetails(s)
	}
	return s.User, nil
}

func (p *AuthnProvider) getRolesAndPerms(s *SessionState) error {
	if p.AuthzUrl == nil || p.AuthzUrl.String() == "" {
		return nil
	}
	authzUrl := *p.AuthzUrl
	authzUrl.Path = "/roles"
	authzUrl.RawQuery = url.Values{"user_id": {s.User}}.Encode()
	req, err := http.NewRequest("GET", authzUrl.String(), nil)
	if err != nil {
		return err
	}
	json, err := api.Request(req)
	if err != nil {
		return err
	}
	s.Roles = json.MustStringArray()
	return nil
}
