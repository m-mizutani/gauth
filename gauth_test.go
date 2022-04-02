package gauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/m-mizutani/gauth"
)

type testClient struct {
	Cookies map[string]*http.Cookie
	handler http.Handler
}

func newTestClient(handler http.Handler) *testClient {
	return &testClient{
		Cookies: make(map[string]*http.Cookie),
		handler: handler,
	}
}

func (x *testClient) ServeHTTP(w *httptest.ResponseRecorder, r *http.Request) {
	for _, cookie := range x.Cookies {
		r.AddCookie(cookie)
	}
	x.handler.ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		x.Cookies[cookie.Name] = cookie
	}
}

func TestGAuthBasicAuthenticationFlow(t *testing.T) {
	token := &gauth.TokenResponse{
		AccessToken: "xyz",
	}
	generatedCode := gauth.RandomToken(32)

	var calledAuthURI, calledGetToken, calledUserInfo int

	r := chi.NewRouter()
	mock := &gauth.OAuth2Mock{
		AuthURI: func(authURI gauth.URI, scopes []string) gauth.URI {
			calledAuthURI++
			return "http://auth.example.com/xxx?client_id=123"
		},
		GetToken: func(ctx context.Context, uri gauth.URI, code gauth.OAuth2Code) (*gauth.TokenResponse, error) {
			calledGetToken++
			assert.Equal(t, generatedCode, string(code))
			return token, nil
		},
		GetUserInfo: func(ctx context.Context, uri gauth.URI, token gauth.AccessToken, out interface{}) error {
			assert.Equal(t, "https://openidconnect.googleapis.com/v1/userinfo", string(uri))
			require.NoError(t, json.Unmarshal([]byte(`{"email":"mizutani@hey.com"}`), out))
			calledUserInfo++
			return nil
		},
	}
	auth := gauth.New(
		gauth.WithOAuth2Factory(gauth.NewOAuth2Mock(mock)),
		gauth.WithGoogleOAuth2("xxx", "yyy", "http://example.net/callback"),
		gauth.WithPolicy(gauth.AllowedAll()),
	)
	r.Use(auth)
	r.Get("/some/path", func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(gauth.CtxUserKey).(*gauth.User)
		if !ok {
			panic("no user data")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(user.Email))
	})

	client := newTestClient(r)
	{
		// redirect to authentication page
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/some/path", nil)
		client.ServeHTTP(w, req)
		require.Equal(t, http.StatusFound, w.Result().StatusCode)
		uri, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "auth.example.com", uri.Host)
		assert.Equal(t, "/xxx", uri.Path)
		assert.Equal(t, "123", uri.Query().Get("client_id"))
	}

	{
		// redirect from authentication page
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.net/callback?code="+generatedCode, nil)
		client.ServeHTTP(w, req)
		require.Equal(t, http.StatusFound, w.Result().StatusCode)
		uri, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "/some/path", uri.Path)
	}

	assert.Equal(t, 1, calledAuthURI)
	assert.Equal(t, 1, calledGetToken)
	assert.Equal(t, 1, calledUserInfo)

	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/some/path", nil)
		client.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	}

}
