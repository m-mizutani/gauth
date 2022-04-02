package gauth

import "net/http"

// Policy is function to determine if a request is allowed. `true` of returned value means "allowed". Default policy is "denied".
type Policy func(r *http.Request, u *User) bool
type Policies []Policy

func (x Policies) allowed(r *http.Request, u *User) bool {
	for _, policy := range x {
		if policy(r, u) {
			return true
		}
	}

	return false
}

// WithPolicy sets policy to decide if user can access. If no policy, all accesses are denied.
func WithPolicy(policies ...Policy) Option {
	return func(n *Middleware) error {
		n.policies = append(n.policies, policies...)
		return nil
	}
}

// AllowedAll is access policy and always returns true (allowed).
func AllowedAll() Policy {
	return func(r *http.Request, u *User) bool {
		return true
	}
}

// AllowedEmailsPolicy is access policy and returns true if email is matched in list.
func AllowedEmails(emailAddrs []string) Policy {
	return func(r *http.Request, u *User) bool {
		if u.Email.IsEmpty() {
			return false
		}
		for i := range emailAddrs {
			if emailAddrs[i] == string(u.Email) {
				return true
			}
		}
		return false
	}
}
