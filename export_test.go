package gauth

import "context"

type OAuth2Mock struct {
	oauth2
	AuthURI     func(authURI URI, scopes []string) URI
	GetToken    func(context.Context, URI, OAuth2Code) (*TokenResponse, error)
	GetUserInfo func(context.Context, URI, AccessToken, interface{}) error
}

func (x *OAuth2Mock) authURI(authURI URI, scopes []string) URI {
	return x.AuthURI(authURI, scopes)
}
func (x *OAuth2Mock) getToken(ctx context.Context, uri URI, code OAuth2Code) (*TokenResponse, error) {
	return x.GetToken(ctx, uri, code)
}
func (x *OAuth2Mock) getUserInfo(ctx context.Context, uri URI, token AccessToken, out interface{}) error {
	return x.GetUserInfo(ctx, uri, token, out)
}

func NewOAuth2Mock(mock *OAuth2Mock) OAuth2Factory {
	return func(_ OAuth2ClientID, _ OAuth2ClientSecret, _ URI) oauth2 {
		return mock
	}
}

var RandomToken = randomToken
