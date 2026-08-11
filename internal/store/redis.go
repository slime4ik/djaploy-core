package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})
	return &RedisCache{client: client}
}

// Installation token management
func (r *RedisCache) SetInstallationToken(ctx context.Context, userID string, token string) error {
	key := fmt.Sprintf("installation_token:%s", userID)
	return r.client.Set(ctx, key, token, 58*time.Minute).Err()
}

func (r *RedisCache) GetInstallationToken(ctx context.Context, userID string) (string, error) {
	key := fmt.Sprintf("installation_token:%s", userID)

	token, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}

	return token, nil
}

func (r *RedisCache) DeleteInstallationToken(ctx context.Context, userID string) error {
	key := fmt.Sprintf("installation_token:%s", userID)

	return r.client.Del(ctx, key).Err()
}

// Repos cache holds the last successful repository list of a user. It exists so a temporary
// failure or timeout talking to GitHub (common from a server in Russia) does not break the
// dashboard: we serve the last known list instead.
func (r *RedisCache) SetReposCache(ctx context.Context, userID string, data []byte) error {
	key := fmt.Sprintf("repos_cache:%s", userID)
	return r.client.Set(ctx, key, data, 30*time.Minute).Err()
}

func (r *RedisCache) GetReposCache(ctx context.Context, userID string) ([]byte, error) {
	key := fmt.Sprintf("repos_cache:%s", userID)
	return r.client.Get(ctx, key).Bytes()
}
