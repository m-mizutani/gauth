package gauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/m-mizutani/goerr"
)

func WithJwtExpiresIn(expiresIn time.Duration) Option {
	return func(n *Middleware) error {
		n.jwt.expiresIn = expiresIn
		return nil
	}
}

func WithJwtSecret(secret string) Option {
	return func(n *Middleware) error {
		n.jwt.secret = tokenSecret(secret)
		return nil
	}
}

type jwtHandler struct {
	secret    tokenSecret
	expiresIn time.Duration
}

func newJwtHandler(secret tokenSecret, expiresIn time.Duration) *jwtHandler {
	return &jwtHandler{
		secret:    secret,
		expiresIn: expiresIn,
	}
}

type jwtClaims struct {
	User
	jwt.RegisteredClaims
}

func (x *jwtHandler) signToken(user *User, now time.Time) (string, error) {
	claims := jwtClaims{
		User: *user,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "gauth",
			Subject:   string(user.Provider) + ":" + user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(x.expiresIn)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(x.secret))
	if err != nil {
		return "", goerr.Wrap(err)
	}

	return signed, nil
}

func (x *jwtHandler) verifyToken(ssnToken sessionToken, now time.Time) (*User, error) {
	parsed, err := jwt.ParseWithClaims(string(ssnToken), &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, goerr.Wrap(ErrInvalidToken, "unexpected signing method").With("alg", token.Header["alg"])
		}

		return []byte(x.secret), nil
	})
	if err != nil {
		fmt.Println("error!!!")
		return nil, ErrInvalidToken.Wrap(err)
	}

	if !parsed.Valid {
		return nil, goerr.Wrap(ErrInvalidToken, "parse failed")
	}

	claims, ok := parsed.Claims.(*jwtClaims)
	if !ok {
		return nil, goerr.Wrap(ErrInvalidToken, "not valid")
	}

	return &claims.User, nil
}
