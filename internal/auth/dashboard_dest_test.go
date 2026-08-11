package auth

import (
	"context"
	"testing"

	"github.com/slime4ik/djaploy-core/internal/cfg"
)

// promo stub: granted=true means the promotion was applied and welcome=max must appear in the URL
type fakePromo struct{ granted bool }

func (f fakePromo) GrantNewUserMax(context.Context, string) bool { return f.granted }

// The signup analytics goal hangs off ?new=1 in the redirect after OAuth. If that parameter ever
// disappears, signups stop being counted silently, so this test pins it down.
func TestDashboardDest(t *testing.T) {
	h := &UserHandler{s: &UserService{cfg: &cfg.Config{FrontendURL: "https://ru.djaploy.dev", PromoNewUserMaxDays: 14}}}

	tests := []struct {
		name  string
		isNew bool
		promo PromoGranter
		want  string
	}{
		{"returning user, nothing extra", false, fakePromo{true}, "https://ru.djaploy.dev/dashboard"},
		{"new user, no promotion", true, fakePromo{false}, "https://ru.djaploy.dev/dashboard?new=1"},
		{"new user with the promotion", true, fakePromo{true}, "https://ru.djaploy.dev/dashboard?days=14&new=1&welcome=max"},
		{"new user, promotion not wired in", true, nil, "https://ru.djaploy.dev/dashboard?new=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.promo = tt.promo
			if got := h.dashboardDest(context.Background(), "user-1", tt.isNew); got != tt.want {
				t.Errorf("dashboardDest() = %q, want %q", got, tt.want)
			}
		})
	}
}
