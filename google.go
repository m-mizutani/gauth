package gauth

import (
	"net/http"
	"net/url"

	"github.com/m-mizutani/goerr"
)

type googleOAuth2 struct {
	oauth2Client oauth2
	callbackPath string
}

type googleOAuthUserInfo struct {
	Email         emailAddress `json:"email"`
	EmailVerified bool         `json:"email_verified"`
	HD            string       `json:"hd"`
	Locale        string       `json:"locale"`
	Name          string       `json:"name"`
	FamilyName    string       `json:"family_name"`
	GivenName     string       `json:"given_name"`
	Picture       string       `json:"picture"`
	Sub           string       `json:"sub"`
}

func (x *googleOAuth2) Validate() error {
	return nil
}

// WithGoogleOAuth2 enables google OAuth2 provider. You can find clientID, clientSecret and callback from OAuth 2.0 Client credential file of such as Google Cloud.
func WithGoogleOAuth2(clientID, clientSecret, callback string) Option {
	return func(n *Middleware) error {
		uri, err := url.Parse(callback)
		if err != nil {
			return goerr.Wrap(err, "OAuth2 callback URI")
		}

		/*
			provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
			if err != nil {
				return goerr.Wrap(err)
			}
		*/

		g := &googleOAuth2{
			oauth2Client: n.newOAuth2(
				OAuth2ClientID(clientID),
				OAuth2ClientSecret(clientSecret),
				URI(callback),
			),
			callbackPath: uri.Path,
		}
		if err := g.Validate(); err != nil {
			return err
		}

		n.google = g
		return nil
	}
}

const (
	googleAuthEndpoint     URI = "https://accounts.google.com/o/oauth2/auth"
	googleTokenEndpoint    URI = "https://oauth2.googleapis.com/token"
	googleUserInfoEndpoint URI = "https://openidconnect.googleapis.com/v1/userinfo"

	googleOAuthScopeUserEmail   = "https://www.googleapis.com/auth/userinfo.email"
	googleOAuthScopeUserProfile = "https://www.googleapis.com/auth/userinfo.profile"
)

func (x *googleOAuth2) Auth(w http.ResponseWriter, r *http.Request) (*User, error) {
	if r.Method == http.MethodGet && r.URL.Path == x.callbackPath {
		return x.callback(w, r)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieCallback,
		Value:    r.URL.Path,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	})

	x.redirectToAuthEndpoint(w, r)
	return nil, nil
}

func (x *googleOAuth2) redirectToAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	scopes := []string{
		googleOAuthScopeUserEmail,
		googleOAuthScopeUserProfile,
	}

	w.Header().Add("Location", string(x.oauth2Client.authURI(googleAuthEndpoint, scopes)))
	w.WriteHeader(http.StatusFound)
	w.Write([]byte("redirect to google auth endpoint"))
}

func (x *googleOAuth2) callback(w http.ResponseWriter, r *http.Request) (*User, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "no code in redirect URI")
	}

	ctx := r.Context()
	token, err := x.oauth2Client.getToken(ctx, googleTokenEndpoint, OAuth2Code(code))
	if err != nil {
		return nil, err
	}

	/*
		token, err := x.verifier.Verify(r.Context(), accessToken.IDToken)
		if err != nil {
			return nil, err
		}
	*/

	var userInfo googleOAuthUserInfo
	x.oauth2Client.getUserInfo(ctx, googleUserInfoEndpoint, token.AccessToken, &userInfo)

	return &User{
		Provider: googleOAuth2Provider,
		Name:     userInfo.Name,
		ID:       userInfo.Sub,
		Email:    userInfo.Email,
	}, nil
}
