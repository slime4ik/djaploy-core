package deploy

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// ServerStats is a snapshot of the user's server resources, taken on request from the dashboard.
// We report AVAILABLE memory rather than used memory: Linux fills memory with cache, so "95% used"
// would scare people on every single server for no reason.
type ServerStats struct {
	DiskUsedPct int             `json:"disk_used_pct"`
	DiskUsed    string          `json:"disk_used"`  // for example "12.3 ГБ"
	DiskTotal   string          `json:"disk_total"` // for example "40 ГБ"
	MemUsedPct  int             `json:"mem_used_pct"`
	MemAvail    string          `json:"mem_avail"` // available memory, for example "1.4 ГБ"
	MemTotal    string          `json:"mem_total"`
	Load1       string          `json:"load1"` // one minute load average
	CPUs        int             `json:"cpus"`
	Containers  []ContainerStat `json:"containers"`
}

// ContainerStat is the state of one project container.
type ContainerStat struct {
	Name   string `json:"name"`
	State  string `json:"state"`  // running | exited | restarting | ...
	Status string `json:"status"` // "Up 3 hours" or "Exited (1) 2 minutes ago"
}

// ServerStats reads the server resources over the stored key. Access is granted to the owner or
// a team member, same as for logs and the VPN config. One SSH round trip, then a compact parse.
func (s *Service) ServerStats(ctx context.Context, id, userID string) (*ServerStats, *DeployError) {
	dep, keyEnc, err := s.repo.getFull(ctx, id)
	if err != nil {
		return nil, derr("not_found", "Проект не найден.", "")
	}
	if !s.canAccess(ctx, dep, userID) {
		return nil, derr("forbidden", "Нет доступа.", "")
	}
	if keyEnc == "" {
		return nil, derr("no_key", "Нет доступа к серверу этого проекта.", "Запусти деплой заново.")
	}
	key, de := s.decryptKey(keyEnc)
	if de != nil {
		return nil, de
	}
	sshc, hkErr, err := dialKeyPinned(ctx, s.repo, dep.UserID, dep.ServerIP, dep.SSHUser, key)
	if hkErr != nil {
		return nil, hkErr
	}
	if err != nil {
		return nil, derr("ssh_failed", "Не удалось подключиться к серверу.", "Возможно, сервер недоступен.")
	}
	defer sshc.Close()

	name := sanitizeName(dep.Repo)
	// One round trip: root disk, available memory, load, cores and the project containers.
	// Each line is tagged at the start so the mixed output parses reliably.
	script := `echo "DISK $(df -P / | awk 'NR==2{print $2, $3, $5}')"
echo "MEM $(free -k | awk '/^Mem:/{print $2, $7}')"
echo "LOAD $(awk '{print $1}' /proc/loadavg)"
echo "CPUS $(nproc 2>/dev/null || echo 1)"
docker ps -a --filter "label=com.docker.compose.project=` + name + `" --format 'CT {{.Names}}|{{.State}}|{{.Status}}' 2>/dev/null || true`

	var lines []string
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := sshc.Run(cctx, script, func(l string) { lines = append(lines, l) }); err != nil && len(lines) == 0 {
		return nil, derr("stats_failed", "Не удалось прочитать состояние сервера.", "Попробуй ещё раз.")
	}
	return parseServerStats(lines), nil
}

func parseServerStats(lines []string) *ServerStats {
	st := &ServerStats{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "DISK": // total_1k used_1k pct%
			if len(f) >= 4 {
				total := atoiKB(f[1])
				used := atoiKB(f[2])
				st.DiskUsedPct = atoiPct(f[3])
				st.DiskUsed = humanKB(used)
				st.DiskTotal = humanKB(total)
			}
		case "MEM": // total_k available_k
			if len(f) >= 3 {
				total := atoiKB(f[1])
				avail := atoiKB(f[2])
				st.MemTotal = humanKB(total)
				st.MemAvail = humanKB(avail)
				if total > 0 {
					st.MemUsedPct = int(float64(total-avail) / float64(total) * 100)
				}
			}
		case "LOAD":
			if len(f) >= 2 {
				st.Load1 = f[1]
			}
		case "CPUS":
			if len(f) >= 2 {
				st.CPUs, _ = strconv.Atoi(f[1])
			}
		case "CT": // CT name|state|status
			rest := strings.TrimSpace(strings.TrimPrefix(l, "CT "))
			parts := strings.SplitN(rest, "|", 3)
			if len(parts) == 3 {
				st.Containers = append(st.Containers, ContainerStat{
					Name: parts[0], State: parts[1], Status: parts[2],
				})
			}
		}
	}
	return st
}

func atoiKB(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func atoiPct(s string) int {
	n, _ := strconv.Atoi(strings.TrimRight(strings.TrimSpace(s), "%"))
	return n
}

// humanKB formats kilobytes as GB or MB with one decimal, for the resources panel.
func humanKB(kb int64) string {
	const mb = 1024
	const gb = 1024 * 1024
	switch {
	case kb >= gb:
		return strconv.FormatFloat(float64(kb)/gb, 'f', 1, 64) + " ГБ"
	case kb >= mb:
		return strconv.FormatFloat(float64(kb)/mb, 'f', 0, 64) + " МБ"
	default:
		return strconv.FormatInt(kb, 10) + " КБ"
	}
}
