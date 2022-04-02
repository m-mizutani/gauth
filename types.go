package gauth

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/m-mizutani/goerr"
)

type (
	gauthContextKey string

	sessionToken string
	tokenSecret  string

	OAuth2Code         string
	OAuth2ClientID     string
	OAuth2ClientSecret string
	URI                string
	emailAddress       string
	authProvider       string

	AccessToken string
)

const (
	CtxUserKey gauthContextKey = "gauth_user"

	cookieTokenName string = "gauth_token"
	cookieCallback  string = "gauth_callback"

	googleOAuth2Provider authProvider = "google"
)

type User struct {
	Provider authProvider
	Name     string
	ID       string
	Email    emailAddress
}

func (x OAuth2ClientID) Validate() error {
	if err := validation.Validate(string(x), validation.Required); err != nil {
		return goerr.Wrap(err, "ClientID")
	}
	return nil
}

func (x OAuth2ClientSecret) Validate() error {
	if err := validation.Validate(string(x), validation.Required); err != nil {
		return goerr.Wrap(err, "ClientSecret")
	}
	return nil
}

func (x URI) Validate() error {
	if err := validation.Validate(string(x), validation.Required, is.URL); err != nil {
		return goerr.Wrap(err, "URI")
	}
	return nil
}

func (x emailAddress) Validate() error {
	if err := validation.Validate(string(x), validation.Required, is.Email); err != nil {
		return goerr.Wrap(err, "Email")
	}
	return nil
}

func (x emailAddress) IsEmpty() bool { return x == "" }
