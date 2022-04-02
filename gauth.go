package gauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/m-mizutani/goerr"
)

// Middleware is main structure of the package. It's configurable by *New* method and *Option*.
type Middleware struct {
	newOAuth2 OAuth2Factory

	google   *googleOAuth2
	policies Policies
	jwt      *jwtHandler
	now      func() time.Time
}

// New provides initialized middleware. If invalid options are given, the method will panic. Use `NewWithError` if you need error handling.
func New(options ...Option) func(http.Handler) http.Handler {
	n, err := NewWithError(options...)
	if err != nil {
		panic(fmt.Sprintf("naberius initialize error: %+v", err))
	}
	return n
}

// NewWithError provides initialized middleware.
func NewWithError(options ...Option) (func(http.Handler) http.Handler, error) {
	n := &Middleware{
		newOAuth2: newOAuth2,
		jwt:       newJwtHandler(randomToken(32), tokenSecret(randomToken(32)), time.Hour*24),
		now:       time.Now,
	}

	for _, opt := range options {
		if err := opt(n); err != nil {
			return nil, err
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.auth(w, r, next)
		})
	}, nil
}

type Option func(n *Middleware) error

func (x *Middleware) auth(w http.ResponseWriter, r *http.Request, next http.Handler) {
	var user *User
	if cookie := lookupCookie(r.Cookies(), cookieTokenName); cookie != nil {
		claims, err := x.jwt.verifyToken(sessionToken(cookie.Value), x.now())
		if err != nil {
			handleError(w, err)
			return
		}

		user = claims
		x.forward(w, r, next, user)
		return
	}

	if x.google != nil {
		resp, err := x.google.Auth(w, r)
		if err != nil {
			handleError(w, err)
			return
		}
		user = resp
	}

	// not authenticated
	if user == nil {
		x.accessDenied(w)
		return
	}

	token, err := x.jwt.signToken(user, x.now())
	if err != nil {
		handleError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieTokenName,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	})

	x.forward(w, r, next, user)
}

func (x *Middleware) accessDenied(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("<html><body><h1>Access denied</h1></body></html>"))
}

func (x *Middleware) forward(w http.ResponseWriter, r *http.Request, next http.Handler, user *User) {
	if !x.policies.allowed(r, user) {
		x.accessDenied(w)
		return
	}

	ctx := context.WithValue(r.Context(), CtxUserKey, user)
	if cookie := lookupCookie(r.Cookies(), cookieCallback); cookie != nil && cookie.Value != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieCallback,
			Value:    "",
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
		})
		http.Redirect(w, r, cookie.Value, http.StatusFound)
		return
	}

	next.ServeHTTP(w, r.WithContext(ctx))
}

func handleError(w http.ResponseWriter, err error) {
	var goErr *goerr.Error
	statusCode := http.StatusInternalServerError
	if errors.As(err, &goErr) {
		values := goErr.Values()
		if code, ok := values["code"].(int); ok {
			statusCode = code
			return
		}
	}

	logger.Error(err.Error())
	logger.Err(err).Info("error detail")

	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(err.Error()))
}
