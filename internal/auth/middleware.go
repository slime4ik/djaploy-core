package auth

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ActiveChecker verifies the user is not banned. Implemented by *UserService.
// It is an interface so the middleware can be covered by tests with a mock.
type ActiveChecker interface {
	IsActive(ctx context.Context, userID string) (bool, error)
}

// CookieClearer holds the cookie clearing parameters for a ban (taken from cfg).
type CookieClearer struct {
	Domain string
	Secure bool
}

// RequireActive is the middleware that blocks banned users (is_active=false).
// It goes AFTER JWTMiddleware (it takes user_id from the context). A banned user gets their
// cookies cleared and a 403, which the frontend sees and logs them out.
// fail-open on a database error: a database outage must NOT log everyone out (a ban is a rare
// admin action, a second during an outage is not critical, and a client cannot fake the outage).
func RequireActive(checker ActiveChecker, cookie CookieClearer) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.Next()
			return
		}
		active, err := checker.IsActive(c.Request.Context(), userID)
		if err != nil {
			log.Printf("auth: проверка бана для %s не удалась (пропускаю): %v", userID, err)
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
