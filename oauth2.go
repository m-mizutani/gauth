package gauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/m-mizutani/goerr"
)

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type oauth2 interface {
	authURI(authURI URI, scopes []string) URI
	getToken(ctx context.Context, uri URI, code OAuth2Code) (*TokenResponse, error)
	getUserInfo(ctx context.Context, uri URI, token AccessToken, out interface{}) error
}

type TokenResponse struct {
	AccessToken  AccessToken `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	IDToken      string      `json:"id_token"`
	ExpiresIn    int64       `json:"expires_in"`
	Scope        string      `json:"scope"`
	TokenType    string      `json:"token_type"`
}

type oauth2Client struct {
	clientID     OAuth2ClientID
	clientSecret OAuth2ClientSecret
	callbackURI  URI

	httpClient httpClient
}

type OAuth2Factory func(OAuth2ClientID, OAuth2ClientSecret, URI) oauth2

func newOAuth2(clientID OAuth2ClientID, clientSecret OAuth2ClientSecret, callbackURI URI) oauth2 {
	return &oauth2Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURI:  callbackURI,

		httpClient: http.DefaultClient,
	}
}

func WithOAuth2Factory(fac OAuth2Factory) Option {
	return func(n *Middleware) error {
		n.newOAuth2 = fac
		return nil
	}
}

func (x *oauth2Client) authURI(authURI URI, scopes []string) URI {
	q := &url.Values{}
	q.Add("client_id", string(x.clientID))
	q.Add("redirect_uri", string(x.callbackURI))
	q.Add("response_type", "code")
	q.Add("scope", strings.Join(scopes, " "))

	return authURI + URI("?"+q.Encode())
}

func (x *oauth2Client) getToken(ctx context.Context, uri URI, code OAuth2Code) (*TokenResponse, error) {
	body := &url.Values{}
	body.Add("grant_type", "authorization_code")
	body.Add("code", string(code))
	body.Add("client_id", string(x.clientID))
	body.Add("client_secret", string(x.clientSecret))
	body.Add("redirect_uri", string(x.callbackURI))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(uri), bytes.NewReader([]byte(body.Encode())))
	if err != nil {
		return nil, goerr.Wrap(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := x.httpClient.Do(req)
	if err != nil {
		return nil, goerr.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "can not read token").With("body", string(body)).With("status", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, goerr.Wrap(err)
	}

	return &token, nil
}

func (x *oauth2Client) getUserInfo(ctx context.Context, uri URI, token AccessToken, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, string(uri), nil)
	if err != nil {
		return goerr.Wrap(err)
	}
	req.Header.Add("Authorization", "Bearer "+string(token))
	resp, err := x.httpClient.Do(req)
	if err != nil {
		return goerr.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "can not read user info").With("body", string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return goerr.Wrap(err)
	}

	return nil
}
