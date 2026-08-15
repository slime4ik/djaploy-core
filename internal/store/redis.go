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

// Close shuts the connection pool down on service stop so redis does not count them as abandoned.
func (r *RedisCache) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	return r.client.Close()
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

// Repos cache holds the last successful repository list of a user. It keeps a temporary GitHub
// failure or timeout (common from a Russian server) from breaking the dashboard: we serve the last known one.
func (r *RedisCache) SetReposCache(ctx context.Context, userID string, data []byte) error {
	key := fmt.Sprintf("repos_cache:%s", userID)
	return r.client.Set(ctx, key, data, 30*time.Minute).Err()
}

func (r *RedisCache) GetReposCache(ctx context.Context, userID string) ([]byte, error) {
	key := fmt.Sprintf("repos_cache:%s", userID)
	return r.client.Get(ctx, key).Bytes()
}
