package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// ActiveChecker mock
type fakeChecker struct {
	active bool
	err    error
}

func (f fakeChecker) IsActive(_ context.Context, _ string) (bool, error) {
	return f.active, f.err
}

func runWith(checker ActiveChecker, userID string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
		c.Next()
	})
	r.Use(RequireActive(checker, CookieClearer{}))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, c.Request)
	return w
}

func TestRequireActive(t *testing.T) {
	t.Run("an active user passes", func(t *testing.T) {
		w := runWith(fakeChecker{active: true}, "u1")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("a banned user gets 403 and cleared cookies", func(t *testing.T) {
		w := runWith(fakeChecker{active: false}, "u1")
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
		setCookie := w.Header().Get("Set-Cookie")
		if setCookie == "" {
			t.Fatal("expected a cookie reset (Set-Cookie), there is none")
		}
	})

	t.Run("a database error fails open, nobody gets signed out", func(t *testing.T) {
		w := runWith(fakeChecker{err: errors.New("db down")}, "u1")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 (fail open), got %d", w.Code)
		}
	})

	t.Run("no user_id, nothing to check", func(t *testing.T) {
		w := runWith(fakeChecker{active: false}, "")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
