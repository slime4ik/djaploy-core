package cfg

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	GitHubClientID         string
	GitHubClientSecret     string
	DatabaseURL            string
	RedisAdress            string
	JWTSecret              string
	GitHunAppID            string
	GitHubAppClientID      string
	GitHubAppSlug          string
	GitHubAppClientSecret  string
	GitHubAppPemPath       string
	GitHubAppWebHookSecret string
	Port                   string

	// URLs and cookies switch between dev and prod through env, with no code changes.
	FrontendURL  string // where the browser goes after OAuth (the SPA)
	PublicURL    string // the public address of the backend itself (for redirect_uri and callbacks)
	CookieDomain string // cookie domain; empty means host-only, which is the recommended setting
	CookieSecure bool   // true in production (https), false locally (http)

	// Payment provider credentials for subscriptions. Optional: without them billing is off.
	YooKassaShopID    string
	YooKassaSecretKey string

	// Secret token for the admin endpoints, used to grant subscriptions by hand. Empty disables them.
	AdminToken string

	// Secret code for the demo login, used by payment provider reviewers. Empty disables it.
	DemoCode string

	// Telegram bot for notifications. Empty disables notifications.
	TelegramBotToken    string
	TelegramBotUsername string

	// Promotion: a new user gets Max for N days on first sign-in, with no card, and drops to free
	// afterwards. 0 disables it. Set through PROMO_NEW_USER_MAX_DAYS, no code changes needed.
	PromoNewUserMaxDays int

	// GitLab OAuth. Optional: when empty the GitLab buttons are hidden and the endpoints answer 501.
	GitLabClientID     string
	GitLabClientSecret string
	GitLabBaseURL      string // https://gitlab.com, leaving room for self-hosted instances
}

// GitLabEnabled reports whether the GitLab provider is configured.
func (c *Config) GitLabEnabled() bool {
	return c.GitLabClientID != "" && c.GitLabClientSecret != ""
}

func Load() (*Config, error) {
	cfg := &Config{
		GitHubClientID:         os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:     os.Getenv("GITHUB_CLIENT_SECRET"),
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		RedisAdress:            os.Getenv("REDIS_ADRESS"),
		JWTSecret:              os.Getenv("JWT_SECRET"),
		GitHunAppID:            os.Getenv("GITHUB_APP_ID"),
		GitHubAppClientID:      os.Getenv("GITHUB_APP_CLIENT_ID"),
		GitHubAppSlug:          os.Getenv("GITHUB_APP_SLUG"),
		GitHubAppClientSecret:  os.Getenv("GITHUB_APP_CLIENT_SECRET"),
		GitHubAppPemPath:       os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
		GitHubAppWebHookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		Port:                   os.Getenv("PORT"),

		FrontendURL:  getenvDefault("FRONTEND_URL", "http://localhost:5173"),
		PublicURL:    getenvDefault("PUBLIC_URL", "http://localhost:8080"),
		CookieDomain: os.Getenv("COOKIE_DOMAIN"),
		CookieSecure: os.Getenv("COOKIE_SECURE") == "true",

		YooKassaShopID:    os.Getenv("YOOKASSA_SHOP_ID"),
		YooKassaSecretKey: os.Getenv("YOOKASSA_SECRET_KEY"),

		AdminToken: os.Getenv("ADMIN_TOKEN"),
		DemoCode:   os.Getenv("DEMO_LOGIN_CODE"),

		TelegramBotToken:    os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramBotUsername: os.Getenv("TELEGRAM_BOT_USERNAME"),

		PromoNewUserMaxDays: atoiDefault(os.Getenv("PROMO_NEW_USER_MAX_DAYS"), 0),

		GitLabClientID:     os.Getenv("GITLAB_CLIENT_ID"),
		GitLabClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
		GitLabBaseURL:      getenvDefault("GITLAB_BASE_URL", "https://gitlab.com"),
	}

	var missing []string

	required := map[string]string{
		"GITHUB_CLIENT_ID":            cfg.GitHubClientID,
		"GITHUB_CLIENT_SECRET":        cfg.GitHubClientSecret,
		"DATABASE_URL":                cfg.DatabaseURL,
		"REDIS_ADRESS":                cfg.RedisAdress,
		"JWT_SECRET":                  cfg.JWTSecret,
		"GITHUB_APP_ID":               cfg.GitHunAppID,
		"GITHUB_APP_CLIENT_ID":        cfg.GitHubAppClientID,
		"GITHUB_APP_SLUG":             cfg.GitHubAppSlug,
		"GITHUB_APP_CLIENT_SECRET":    cfg.GitHubAppClientSecret,
		"GITHUB_APP_PRIVATE_KEY_PATH": cfg.GitHubAppPemPath,
	}

	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// getenvDefault returns the env value, or the default when the variable is empty.
func getenvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// atoiDefault parses an integer from a string, returning def when it is empty or invalid.
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
