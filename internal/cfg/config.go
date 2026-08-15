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

	// URLs and cookies: switch dev↔prod through env, without touching code.
	FrontendURL  string // куда редиректим браузер после OAuth (SPA)
	PublicURL    string // публичный адрес самого бэка (для redirect_uri/callback)
	CookieDomain string // домен куки; пусто = host-only (рекомендуется)
	CookieSecure bool   // true в проде (https), false локально (http)

	// YooKassa: subscription payments (optional, without them billing is off).
	YooKassaShopID    string
	YooKassaSecretKey string

	// Secret token for the admin endpoints (granting subscriptions by hand). Empty = admin off.
	AdminToken string

	// Secret demo login code (for YooKassa moderators). Empty = demo login off.
	DemoCode string

	// Telegram bot for notifications. Empty = notifications off.
	TelegramBotToken    string
	TelegramBotUsername string

	// Promo: new users get Max for N days on first login (no card, then back to free).
	// 0 = off. Changed through PROMO_NEW_USER_MAX_DAYS without touching code.
	PromoNewUserMaxDays int
	// How many days of Max we add for the FIRST successful deploy (0 = off).
	// The welcome days start at signup, but before the first deploy there is still a server to buy:
	// this bonus starts when the product actually began to be used.
	PromoFirstDeployDays int

	// GitLab OAuth (optional: empty hides the GitLab buttons and the endpoints answer 501).
	GitLabClientID     string
	GitLabClientSecret string
	GitLabBaseURL      string // https://gitlab.com; задел под self-hosted
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

		PromoNewUserMaxDays:  atoiDefault(os.Getenv("PROMO_NEW_USER_MAX_DAYS"), 0),
		PromoFirstDeployDays: atoiDefault(os.Getenv("PROMO_FIRST_DEPLOY_DAYS"), 7),

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

// atoiDefault parses an int from a string, returning def when it is empty or invalid.
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
