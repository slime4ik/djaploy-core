package auth

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ActiveChecker verifies that a user is not banned. *UserService implements it.
// It is an interface so the middleware can be tested with a mock.
type ActiveChecker interface {
	IsActive(ctx context.Context, userID string) (bool, error)
}

// CookieClearer holds the cookie settings used to clear a session on a ban (taken from cfg).
type CookieClearer struct {
	Domain string
	Secure bool
}

// RequireActive is the middleware that blocks banned users (is_active=false).
// It goes AFTER JWTMiddleware, since it reads user_id from the context. A banned user gets their
// cookies cleared and a 403, which the frontend turns into a sign-out.
// It fails open on a database error: an outage must NOT sign everybody out. Banning is a rare
// admin action, a second of leeway during an outage is harmless, and a client cannot cause the
// outage to get around the check.
func RequireActive(checker ActiveChecker, cookie CookieClearer) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.Next()
			return
		}
		active, err := checker.IsActive(c.Request.Context(), userID)
		if err != nil {
			log.Printf("auth: ban check for %s failed, letting the request through: %v", userID, err)
			c.Next()
			return
		}
		if !active {
			c.SetCookie("access_token", "", -1, "/", cookie.Domain, cookie.Secure, true)
			c.SetCookie("refresh_token", "", -1, "/", cookie.Domain, cookie.Secure, true)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "account_disabled"})
			return
		}
		c.Next()
	}
}
