package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"github.com/m-mizutani/gauth"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Use(gauth.New(
		gauth.WithGoogleOAuth2(
			os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_CALLBACK_URI"),
		),
		gauth.WithJwtHandler(
			os.Getenv("JWT_ISSUER_NAME"),
			os.Getenv("JWT_SECRET"),
			time.Hour*24,
		),
		gauth.WithPolicy(gauth.AllowedAll()),
	))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(gauth.CtxUserKey).(*gauth.User)
		if !ok {
			panic("no user data")
		}

		body := fmt.Sprintf(`<html><body><h1>Hello, %s</h1></body></html>`, user.Name)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})

	fmt.Println("starting http://127.0.0.1:3333")
	http.ListenAndServe("127.0.0.1:3333", r)
}
