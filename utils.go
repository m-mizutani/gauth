package gauth

import (
	cryptoRand "crypto/rand"
	"net/http"

	"math"
	"math/big"
	"math/rand"

	"github.com/m-mizutani/zlog"
	"github.com/m-mizutani/zlog/filter"
)

var random *rand.Rand

var logger = zlog.New(
	zlog.WithFilters(
		filter.Type(sessionToken("")),
		filter.Type(tokenSecret("")),
		filter.Type(OAuth2Code("")),
		filter.Type(OAuth2ClientSecret("")),
		filter.Type(AccessToken("")),
	),
	zlog.WithLogLevel("fatal"),
)

// WithLogLevel sets log level from [trace|debug|info|warn|error|fatal] for debugging. Default log level is *fatal*. Log level is process wide.
func WithLogLevel(level string) {
	logger = logger.Clone(zlog.WithLogLevel(level))
}

func init() {
	seed, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic("failed init random seed" + err.Error())
	}
	// #nosec: using crypto/rand for math/rand.seed
	random = rand.New(rand.NewSource(seed.Int64()))
}

const randomCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomToken(n int) string {
	token := make([]byte, n)
	for i := 0; i < n; i++ {
		token[i] = randomCharSet[random.Intn(len(randomCharSet))]
	}
	return string(token)
}

func lookupCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for i := range cookies {
		if cookies[i].Name == name {
			return cookies[i]
		}
	}
	return nil
}
