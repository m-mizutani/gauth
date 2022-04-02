package gauth

import "github.com/m-mizutani/goerr"

var (
	ErrInvalidGoogleOAuth2Proc = goerr.New("invalid google oauth2 procedure")
	ErrInvalidToken            = goerr.New("invalid or unavailable token")
)
