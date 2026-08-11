package deploy

import (
	"context"
	"strconv"
	"strings"
	"time"
)

const (
	settingMaintenance = "maintenance_mode"
	settingOwnerChat   = "owner_chat_id"
)

// errMaintenance rejects new deploys during maintenance (we drain them before a restart).
func errMaintenance() *DeployError {
	return derr("maintenance",
		"🛠 Идут технические работы — новые деплои на паузе.",
		"Попробуй через несколько минут. Уже запущенные деплои завершатся штатно.")
}

// MaintenanceOn reports whether maintenance mode is on (a flag in app_settings).
func (r *Repo) MaintenanceOn(ctx context.Context) bool {
	var v string
	err := r.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key=$1`, settingMaintenance).Scan(&v)
	return err == nil && v == "on"
}

// OwnerChatID is the owner's Telegram chat_id for service alerts (0 when unset).
func (r *Repo) OwnerChatID(ctx context.Context) int64 {
	var v string
	if err := r.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key=$1`, settingOwnerChat).Scan(&v); err != nil {
		return 0
	}
	id, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return id
}

// countActiveDeploys returns how many deploys are still running (used to drain before maintenance).
func (r *Repo) countActiveDeploys(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM deployments WHERE status IN ('queued','running')`).Scan(&n)
	return n, err
}

// StartMaintenanceWatcher is a background loop: once maintenance is on and no deploys are
// active, it pings the owner on Telegram once to say the release can go out. The ping flag resets
// when maintenance is switched off.
func (s *Service) StartMaintenanceWatcher() {
	go func() {
		var pinged bool
		for range time.Tick(10 * time.Second) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if !s.repo.MaintenanceOn(ctx) {
				pinged = false
				cancel()
				continue
			}
			n, err := s.repo.countActiveDeploys(ctx)
			if err == nil && n == 0 && !pinged {
				if chat := s.repo.OwnerChatID(ctx); chat != 0 && s.notifier != nil {
					s.notifier.NotifyChat(chat, "✅ Тех-работы: все деплои доработали, активных 0 — можно катить обновление.")
				}
				pinged = true
			}
			cancel()
		}
	}()
}
