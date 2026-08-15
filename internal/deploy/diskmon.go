package deploy

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Disk alert threshold and hysteresis (so we do not send "full/freed" on every percent near the edge).
const (
	diskAlertAt   = 90 // алерт, когда занято ≥ 90%
	diskClearAt   = 85 // «отпустило», когда опустилось ниже 85%
	diskCheckTick = 15 * time.Minute
)

// serverMon represents one server for monitoring purposes (one per server_ip).
type serverMon struct {
	depID    string
	serverIP string
	sshUser  string
	keyEnc   string
	userID   string
	teamID   string
}

// MonitoredServers returns one deployment per server for users and teams whose paid plan is
// active, which is what enables monitoring. Only successful deploys with an access key count.
func (r *Repo) MonitoredServers(ctx context.Context) ([]serverMon, error) {
	const q = `
		SELECT DISTINCT ON (d.server_ip)
		       d.id, d.server_ip, d.ssh_user, d.ssh_key_enc, d.user_id, COALESCE(d.team_id,'')
		FROM deployments d
		LEFT JOIN subscriptions sub ON sub.user_id=d.user_id
			AND sub.plan='max' AND sub.status='active'
			AND sub.current_period_end IS NOT NULL AND sub.current_period_end > NOW()
		LEFT JOIN teams t ON t.id=d.team_id
			AND t.plan='team' AND t.status='active'
			AND t.current_period_end IS NOT NULL AND t.current_period_end > NOW()
		WHERE d.status='success' AND d.ssh_key_enc IS NOT NULL AND d.ssh_key_enc <> ''
		  AND (sub.user_id IS NOT NULL OR t.id IS NOT NULL)
		ORDER BY d.server_ip, d.created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []serverMon
	for rows.Next() {
		var m serverMon
		var key sql.NullString
		if err := rows.Scan(&m.depID, &m.serverIP, &m.sshUser, &key, &m.userID, &m.teamID); err != nil {
			return nil, err
		}
		m.keyEnc = key.String
		out = append(out, m)
	}
	return out, rows.Err()
}

// StartDiskMonitor is a background loop: every diskCheckTick it checks the disk on monitored
// users' servers and alerts once usage reaches diskAlertAt (with hysteresis). Servers are
// deduplicated by server_ip, so there is one alert per server rather than one per project.
func (s *Service) StartDiskMonitor() {
	go func() {
		// warm-up: the first check runs a minute after start, then on every tick
		time.Sleep(1 * time.Minute)
		for {
			s.checkDisks()
			time.Sleep(diskCheckTick)
		}
	}()
}

// diskAlerted remembers whether the "disk is full" alert was already sent for a server.
var diskAlerted sync.Map // server_ip -> bool

// diskCheckWorkers is how many servers we poll at once. Going through them one by one was a
// bottleneck: a single dead server holds the connection until the timeout (20s), and a couple of dozen
// of those stretch the cycle to ten minutes. The limit keeps us from opening a hundred ssh sessions at once.
const diskCheckWorkers = 8

func (s *Service) checkDisks() {
	if s.notifier == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	servers, err := s.repo.MonitoredServers(ctx)
	cancel()
	if err != nil {
		return
	}

	sem := make(chan struct{}, diskCheckWorkers)
	var wg sync.WaitGroup
	for _, m := range servers {
		wg.Add(1)
		go func(m serverMon) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pct, ok := s.serverDiskPct(m)
			if !ok {
				return
			}
			alerted, _ := diskAlerted.Load(m.serverIP)
			wasAlerted, _ := alerted.(bool)

			// The notification goes out on its own context: the caller's could have expired while we waited on ssh.
			nctx, ncancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer ncancel()
			switch {
			case pct >= diskAlertAt && !wasAlerted:
				diskAlerted.Store(m.serverIP, true)
				s.notifyServer(nctx, m, "⚠️ Диск сервера "+m.serverIP+" заполнен на "+strconv.Itoa(pct)+
					"%. Почисти образы: docker system prune -a — или расширь диск. Иначе следующий деплой упадёт с «no space left».")
			case pct < diskClearAt && wasAlerted:
				diskAlerted.Store(m.serverIP, false)
				s.notifyServer(nctx, m, "🟢 Диск сервера "+m.serverIP+" снова в норме ("+strconv.Itoa(pct)+"% занято).")
			}
		}(m)
	}
	wg.Wait()
}

// serverDiskPct returns how full the root partition is, in percent, over the stored key.
func (s *Service) serverDiskPct(m serverMon) (int, bool) {
	if m.keyEnc == "" {
		return 0, false
	}
	key, de := s.decryptKey(m.keyEnc)
	if de != nil {
		return 0, false
	}
	// A background check never pins a host key: an unknown server is simply skipped, and a swapped
	// one is reported once (it is a security event, staying quiet is not an option).
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	sshc, hkErr, err := dialKeyVerifyOnly(ctx, s.repo, m.userID, m.serverIP, m.sshUser, key)
	cancel()
	if hkErr != nil {
		s.alertHostKeyOnce(m, hkErr)
		return 0, false
	}
	if err != nil {
		return 0, false // сервер недоступен — не наша забота (аптайм-монитор это ловит)
	}
	defer sshc.Close()
	var out string
	cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = sshc.Run(cctx, `df -P / | awk 'NR==2{print $5}'`, func(l string) { out += l })
	pct, err := strconv.Atoi(strings.TrimRight(strings.TrimSpace(out), "%"))
	if err != nil {
		return 0, false
	}
	return pct, true
}

// hostKeyAlerted remembers which servers we already reported a swapped key for, so it is one alert
// per server rather than one per tick. Cleared when the user confirms the server was rebuilt.
var hostKeyAlerted sync.Map // server_ip -> bool

// alertHostKeyOnce warns about a host key mismatch exactly once. It uses the "deploys" category
// rather than "disk", because this is a security event and the disk toggle defaults to off.
func (s *Service) alertHostKeyOnce(m serverMon, de *DeployError) {
	if de.Code != "host_key_mismatch" {
		return // незнакомый сервер (пин ещё не поставлен) — молча пропускаем
	}
	if _, seen := hostKeyAlerted.LoadOrStore(m.serverIP, true); seen {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	text := "🔒 Сервер " + m.serverIP + " предъявил другой SSH-ключ. Деплой и мониторинг на него остановлены. " +
		"Если ты пересоздавал сервер — подтверди новый ключ на дашборде. Если нет — проверь сервер, возможен перехват трафика."
	if m.teamID != "" {
		s.notifier.NotifyTeam(ctx, m.teamID, "deploys", text)
	} else {
		s.notifier.Notify(ctx, m.userID, "deploys", text)
	}
}

// notifyServer alerts the owner (or the whole team) in the disk category, which has its own toggle.
func (s *Service) notifyServer(ctx context.Context, m serverMon, text string) {
	if m.teamID != "" {
		s.notifier.NotifyTeam(ctx, m.teamID, "disk", text)
	} else {
		s.notifier.Notify(ctx, m.userID, "disk", text)
	}
}
