package deploy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"
)

// Server access without a password. We generate the key pair on our side and show the user ONE
// line plus the command that puts it into their own authorized_keys. We never ask for and never
// see the server password, and the user revokes access with one line (or a button), because they
// know exactly where it sits: ~/.ssh/authorized_keys, comment djaploy-xxxxxxxx.
//
// The key belongs to a server+ssh-user pair, not to a project: a second project on the same server
// reuses the access already granted, and our line in authorized_keys stays the only one.

const accessAuthPath = "~/.ssh/authorized_keys"

// accessKey is a server_access_keys row (the private half is encrypted).
type accessKey struct {
	IP         string
	SSHUser    string
	Label      string
	PubLine    string
	PrivEnc    string
	CreatedAt  time.Time
	VerifiedAt *time.Time
}

// AccessKeyView is what the user sees. No "just trust us": exactly what now sits on their server,
// and both commands (grant and revoke) in full, so they can be read with your own eyes.
type AccessKeyView struct {
	ServerIP   string     `json:"server_ip"`
	SSHUser    string     `json:"ssh_user"`
	Label      string     `json:"label"`
	PubLine    string     `json:"pub_line"`
	AuthPath   string     `json:"auth_path"`
	InstallCmd string     `json:"install_cmd"` // с машины юзера (через ssh)
	InstallOn  string     `json:"install_on"`  // если он уже в консоли сервера
	RevokeCmd  string     `json:"revoke_cmd"`  // с машины юзера
	RevokeOn   string     `json:"revoke_on"`   // в консоли сервера
	CreatedAt  time.Time  `json:"created_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	HostFP     string     `json:"host_fingerprint,omitempty"` // отпечаток сервера, который мы запомнили
	Projects   int        `json:"projects"`                   // сколько проектов на этом сервере зависят от доступа
	Installed  string     `json:"installed"`                  // user = строку добавил юзер, deploy = положили мы при деплое по паролю
}

// AccessCheck is what we saw on the server after coming in on the granted key.
type AccessCheck struct {
	OK     bool   `json:"ok"`
	OS     string `json:"os,omitempty"`
	Root   bool   `json:"root"`
	SudoOK bool   `json:"sudo_ok"` // root или sudo без пароля, иначе деплою не хватит прав
	HostFP string `json:"host_fingerprint,omitempty"`
}

// AccessRevoke is the result of a revoke: whether the line came off (we may not have reached the server) and how to do it by hand.
type AccessRevoke struct {
	Removed   bool   `json:"removed"`
	RevokeCmd string `json:"revoke_cmd"`
	RevokeOn  string `json:"revoke_on"`
	PubLine   string `json:"pub_line"`
}

// newAccessLabel builds the key comment. It doubles as the revoke anchor: the user finds the line
// in authorized_keys by it, and the sed in the revoke command matches on it too.
func newAccessLabel() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "djaploy"
	}
	return "djaploy-" + hex.EncodeToString(b)
}

// validAccessUser checks an ssh user name is safe to paste into the command we show.
func validAccessUser(u string) bool {
	if u == "" || len(u) > 32 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// installOnServer is the command for the server's own console (the user is already there: the
// provider web console or an open ssh session). The key appears ONCE: a repeat is caught by the
// label rather than the whole line, otherwise the command cannot be read without scrolling sideways.
func installOnServer(pubLine, label string) string {
	guard := label
	if guard == "" {
		guard = pubLine // у старых ключей метки нет, сверяем по самой строке
	}
	return `umask 077; mkdir -p ~/.ssh; grep -q "` + guard + `" ~/.ssh/authorized_keys 2>/dev/null || ` +
		`echo "` + pubLine + `" >> ~/.ssh/authorized_keys`
}

// installCommand is the same thing from the user's machine. It only contains double quotes inside,
// so the whole command wraps in single quotes and survives a paste into bash, zsh and PowerShell.
func installCommand(sshUser, ip, pubLine, label string) string {
	return "ssh " + sshUser + "@" + ip + " '" + installOnServer(pubLine, label) + "'"
}

// revokeOnServer cuts our line out. By the label when there is one, otherwise by the key line itself.
func revokeOnServer(pubLine, label string) string {
	if label != "" {
		return `sed -i "/` + label + `/d" ~/.ssh/authorized_keys`
	}
	ak := "~/.ssh/authorized_keys"
	return `grep -vF "` + pubLine + `" ` + ak + " > " + ak + ".new; mv " + ak + ".new " + ak
}

// revokeCommand is the revoke from the user's machine. They need it before revoking anything: seeing
// what turns it off matters more than pressing a button.
func revokeCommand(sshUser, ip, pubLine, label string) string {
	return "ssh " + sshUser + "@" + ip + " '" + revokeOnServer(pubLine, label) + "'"
}

// ── service ──────────────────────────────────────────────────────────────────

// normalizeTarget is the shared "where are we granting access" validation for every endpoint.
func normalizeTarget(ip, sshUser string) (string, string, *DeployError) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", derr("bad_input", "IP сервера некорректен: "+ip,
			"Укажи IP-адрес твоего сервера, например 203.0.113.10.")
	}
	// same SSRF guard as on deploy: access is granted for a public address only
	if !isPublicIP(parsed) {
		return "", "", derr("bad_input", "Этот IP не похож на публичный адрес сервера: "+ip,
			"Укажи внешний (публичный) IP твоего VPS.")
	}
	sshUser = strings.TrimSpace(sshUser)
	if sshUser == "" {
		sshUser = "root"
	}
	if !validAccessUser(sshUser) {
		return "", "", derr("bad_input", "Имя SSH-пользователя выглядит странно: "+sshUser,
			"Обычно это root. Допустимы латиница, цифры, точка, дефис и подчёркивание.")
	}
	return ip, sshUser, nil
}

// EnsureAccess issues a key for a server (or returns the one already issued). We never reissue:
// the line the user has already added would quietly turn into junk.
func (s *Service) EnsureAccess(ctx context.Context, userID, ip, sshUser string) (*AccessKeyView, *DeployError) {
	ip, sshUser, de := normalizeTarget(ip, sshUser)
	if de != nil {
		return nil, de
	}
	k, err := s.repo.AccessKey(ctx, userID, ip, sshUser)
	if err != nil {
		log.Printf("access: read %s@%s: %v", sshUser, ip, err)
		return nil, derr("internal", "Не удалось прочитать ключ доступа.", "Попробуй ещё раз.")
	}
	// Our key from earlier password deploys is already on the server. No reason to ask the user for
	// a second line: we show what is there, and the deploy will go in on it.
	if k == nil {
		if old := s.deployedKey(ctx, userID, ip, sshUser); old != nil {
			v := s.accessView(ctx, userID, old)
			v.Installed = "deploy"
			now := time.Now()
			v.VerifiedAt = &now
			return v, nil
		}
	}
	if k == nil {
		priv, pub, gerr := genSSHKey()
		if gerr != nil {
			log.Printf("access: genkey: %v", gerr)
			return nil, derr("internal", "Не удалось сгенерировать ключ.", "Попробуй ещё раз.")
		}
		enc, eerr := encrypt(s.encKey, priv)
		if eerr != nil {
			log.Printf("access: encrypt: %v", eerr)
			return nil, derr("internal", "Не удалось сохранить ключ.", "Попробуй ещё раз.")
		}
		label := newAccessLabel()
		k, err = s.repo.SaveAccessKey(ctx, userID, &accessKey{
			IP: ip, SSHUser: sshUser, Label: label,
			PubLine: pub + " " + label, PrivEnc: enc,
		})
		if err != nil {
			log.Printf("access: save %s@%s: %v", sshUser, ip, err)
			return nil, derr("internal", "Не удалось сохранить ключ доступа.", "Попробуй ещё раз.")
		}
	}
	return s.accessView(ctx, userID, k), nil
}

// CheckAccess verifies the user added the line by trying the key. It also looks at the rights we get
// (root or passwordless sudo), so the user learns about that here and not halfway through a deploy.
func (s *Service) CheckAccess(ctx context.Context, userID, ip, sshUser string) (*AccessCheck, *DeployError) {
	ip, sshUser, de := normalizeTarget(ip, sshUser)
	if de != nil {
		return nil, de
	}
	k, err := s.repo.AccessKey(ctx, userID, ip, sshUser)
	if err == nil && k == nil {
		k = s.deployedKey(ctx, userID, ip, sshUser) // ключ с прошлых деплоев по паролю
	}
	if err != nil || k == nil {
		return nil, derr("no_access", "Ключ для этого сервера ещё не выдан.",
			"Обнови страницу, и мы сгенерируем строку для authorized_keys.")
	}
	key, de := s.decryptKey(k.PrivEnc)
	if de != nil {
		return nil, de
	}
	dctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	sshc, hkErr, err := dialKeyPinned(dctx, s.repo, userID, ip, sshUser, key)
	if hkErr != nil {
		return nil, hkErr
	}
	if err != nil {
		return nil, derr("access_not_ready", "Сервер "+ip+" пока не пускает нас по этому ключу.",
			"Выполни команду в своём терминале (ту, что выше) и нажми «Проверить» ещё раз. "+
				"Если только что выполнил, подожди пару секунд. Проверь, что заходишь под «"+sshUser+"», "+
				"что порт 22 открыт и что в sshd_config разрешён вход по ключу (PubkeyAuthentication yes).")
	}
	defer sshc.Close()

	out := sshCapture(sshc, `echo "uid=$(id -u)"; . /etc/os-release 2>/dev/null; echo "os=${PRETTY_NAME:-}"; `+
		`sudo -n true 2>/dev/null && echo "sudo=1" || echo "sudo=0"`)
	res := &AccessCheck{OK: true}
	for _, line := range strings.Split(out, "\n") {
		name, val, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch name {
		case "uid":
			res.Root = val == "0"
		case "os":
			res.OS = val
		case "sudo":
			res.SudoOK = val == "1"
		}
	}
	res.SudoOK = res.SudoOK || res.Root
	if fp, _, ok := s.repo.HostPin(ctx, userID, ip); ok {
		res.HostFP = fp
	}
	if err := s.repo.MarkAccessVerified(ctx, userID, ip, sshUser); err != nil {
		log.Printf("access: mark verified %s@%s: %v", sshUser, ip, err)
	}
	return res, nil
}

// RevokeAccess revokes access: it takes the line off the server AND destroys our half of the key.
// If the server was unreachable we still drop our half (it is useless to us anyway) and hand back
// the command the user can run to clear the line themselves.
func (s *Service) RevokeAccess(ctx context.Context, userID, ip, sshUser string, force bool) (*AccessRevoke, *DeployError) {
	ip, sshUser, de := normalizeTarget(ip, sshUser)
	if de != nil {
		return nil, de
	}
	k, err := s.repo.AccessKey(ctx, userID, ip, sshUser)
	if err != nil {
		log.Printf("access: read %s@%s: %v", sshUser, ip, err)
		return nil, derr("internal", "Не удалось прочитать ключ доступа.", "Попробуй ещё раз.")
	}
	if k == nil {
		// We put this key there ourselves on the first password deploy (how it worked before the user
		// granted access). Revoking is the same: take the line off and forget the key, just look in deploys.
		if k = s.deployedKey(ctx, userID, ip, sshUser); k == nil {
			return nil, derr("not_found", "Доступ к этому серверу уже отозван.", "")
		}
	}
	// Same case as deleting a project: a running deploy holds an open session and will finish, but its
	// next step (redeploy, logs) would fail. Better to let it play out.
	if s.store.BusyOn(userID, ip) {
		return nil, derr("busy", "На этом сервере сейчас идёт деплой.",
			"Дождись, пока он закончится, и отзови доступ ещё раз.")
	}
	if n := s.repo.CountDeploymentsOn(ctx, userID, ip, ""); n > 0 && !force {
		return nil, derr("access_in_use",
			"На этом сервере "+itoa(n)+" "+plural(n, "проект", "проекта", "проектов")+" djaploy.",
			"Сами сайты продолжат работать, но обновлять их и делать авто-деплой мы больше не сможем: "+
				"для этого пришлось бы выдать доступ заново. Подтверди, если всё равно отзываем.")
	}
	out := &AccessRevoke{
		RevokeCmd: revokeCommand(k.SSHUser, k.IP, k.PubLine, k.Label),
		RevokeOn:  revokeOnServer(k.PubLine, k.Label),
		PubLine:   k.PubLine,
	}
	if key, kde := s.decryptKey(k.PrivEnc); kde == nil {
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		sshc, _, derr2 := dialKeyPinned(dctx, s.repo, userID, ip, sshUser, key)
		if derr2 == nil {
			// We run exactly the command we show the user and then check the result: quietly reporting
			// "removed" without removing anything is worse than telling the truth.
			cmd := revokeOnServer(k.PubLine, k.Label) +
				"; grep -qF " + sq(k.PubLine) + " ~/.ssh/authorized_keys 2>/dev/null && echo dj_still_there || echo dj_gone"
			out.Removed = strings.Contains(sshCapture(sshc, cmd), "dj_gone")
			sshc.Close()
		}
		cancel()
	}
	if err := s.repo.DeleteAccessKey(ctx, userID, ip, sshUser); err != nil {
		log.Printf("access: delete %s@%s: %v", sshUser, ip, err)
		return nil, derr("internal", "Не удалось отозвать доступ.", "Попробуй ещё раз.")
	}
	// We also forget the project keys on this server: we can no longer use them, and a redeploy should
	// honestly say "grant access again" instead of dying during authentication.
	if err := s.repo.ClearDeploymentKeys(ctx, userID, ip, sshUser); err != nil {
		log.Printf("access: clear deployment keys %s@%s: %v", sshUser, ip, err)
	}
	s.logActivityRaw(userID, "", "", sshUser+"@"+ip, "access", "ok", "доступ отозван")
	if s.notifier != nil {
		text := "🔑 Доступ к серверу " + tgSpoiler(ip) + " отозван: наш ключ удалён у нас"
		if out.Removed {
			text += " и снят с сервера"
		}
		s.notifier.Notify(ctx, userID, "deploys", text)
	}
	return out, nil
}

// ListAccess lists all of the user's accesses (what sits where). Besides granted keys it shows the old
// ones we installed ourselves during password deploys: the user needs to see ALL of our lines, not
// only the ones the new scheme created.
func (s *Service) ListAccess(ctx context.Context, userID string) []AccessKeyView {
	keys, err := s.repo.ListAccessKeys(ctx, userID)
	if err != nil {
		log.Printf("access: list %s: %v", userID, err)
		return []AccessKeyView{}
	}
	seen := map[string]bool{}
	out := make([]AccessKeyView, 0, len(keys))
	for i := range keys {
		seen[keys[i].IP+"|"+keys[i].SSHUser] = true
		out = append(out, *s.accessView(ctx, userID, &keys[i]))
	}
	for _, t := range s.repo.DeploymentAccessTargets(ctx, userID) {
		if seen[t.IP+"|"+t.SSHUser] {
			continue
		}
		if k := s.keyFromEnc(t.IP, t.SSHUser, t.KeyEnc); k != nil {
			v := s.accessView(ctx, userID, k)
			v.Installed = "deploy" // строку положили мы сами, когда заходили по паролю
			out = append(out, *v)
		}
	}
	return out
}

// deployedKey is the key we put on the server ourselves during a password deploy (the old scheme).
func (s *Service) deployedKey(ctx context.Context, userID, ip, sshUser string) *accessKey {
	for _, t := range s.repo.DeploymentAccessTargets(ctx, userID) {
		if t.IP == ip && t.SSHUser == sshUser {
			return s.keyFromEnc(ip, sshUser, t.KeyEnc)
		}
	}
	return nil
}

// keyFromEnc builds an accessKey from an encrypted deploy key. Such keys carry no label (we never
// added one), so revoking them matches on the key line itself instead of the comment.
func (s *Service) keyFromEnc(ip, sshUser, enc string) *accessKey {
	priv, de := s.decryptKey(enc)
	if de != nil {
		return nil
	}
	line, err := pubLineFromPriv(priv)
	if err != nil {
		return nil
	}
	return &accessKey{IP: ip, SSHUser: sshUser, PubLine: line, PrivEnc: enc}
}

// accessKeyPEM decides which key to connect with. The order matters and once cost us a bug: ANY
// granted key used to come first, even when the user pressed "grant access" and never added the line
// to the server. Such a dead key shadowed a working team key, and the deploy died on connecting while
// a neighbouring project of the same team on the same server updated just fine.
// So the keys we KNOW work come first.
func (s *Service) accessKeyPEM(ctx context.Context, userID, teamID, ip, sshUser string) (string, *DeployError) {
	granted, err := s.repo.AccessKey(ctx, userID, ip, sshUser)
	if err != nil {
		log.Printf("access: read %s@%s: %v", sshUser, ip, err)
	}

	// 1. Our own granted key that we have already connected with.
	if granted != nil && granted.VerifiedAt != nil {
		return s.decryptKey(granted.PrivEnc)
	}
	// 2. Our own key from earlier deploys to this server.
	if old := s.deployedKey(ctx, userID, ip, sshUser); old != nil {
		return s.decryptKey(old.PrivEnc)
	}
	// 3. A team project key on this server: the member has it available anyway.
	if shared := s.sharedKeyPEM(ctx, userID, teamID, ip, sshUser); shared != "" {
		return shared, nil
	}
	// 4. Granted but not verified yet: maybe the line was added and "check" was never pressed.
	if granted != nil {
		return s.decryptKey(granted.PrivEnc)
	}
	return "", derr("no_access", "Мы пока не можем зайти на "+ip+" под «"+sshUser+"».",
		"Выдай доступ: скопируй строку из шага «Доступ к серверу» и выполни её у себя в терминале. "+
			"Пароль от сервера нам не нужен.")
}

func (s *Service) accessView(ctx context.Context, userID string, k *accessKey) *AccessKeyView {
	v := &AccessKeyView{
		ServerIP:   k.IP,
		SSHUser:    k.SSHUser,
		Label:      k.Label,
		PubLine:    k.PubLine,
		AuthPath:   accessAuthPath,
		InstallCmd: installCommand(k.SSHUser, k.IP, k.PubLine, k.Label),
		InstallOn:  installOnServer(k.PubLine, k.Label),
		RevokeCmd:  revokeCommand(k.SSHUser, k.IP, k.PubLine, k.Label),
		RevokeOn:   revokeOnServer(k.PubLine, k.Label),
		Installed:  "user",
		CreatedAt:  k.CreatedAt,
		VerifiedAt: k.VerifiedAt,
		Projects:   s.repo.CountDeploymentsOn(ctx, userID, k.IP, ""),
	}
	if fp, _, ok := s.repo.HostPin(ctx, userID, k.IP); ok {
		v.HostFP = fp
	}
	return v
}

// plural picks the Russian form: "1 проект / 2 проекта / 5 проектов".
func plural(n int, one, few, many string) string {
	n = n % 100
	if n >= 11 && n <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	}
	return many
}

// ── storage ──────────────────────────────────────────────────────────────────

// AccessKey returns the granted key, or (nil, nil) when access was never granted.
func (r *Repo) AccessKey(ctx context.Context, userID, ip, sshUser string) (*accessKey, error) {
	const q = `SELECT server_ip, ssh_user, label, pub_line, priv_enc, created_at, verified_at
	           FROM server_access_keys WHERE user_id=$1 AND server_ip=$2 AND ssh_user=$3`
	var k accessKey
	err := r.db.QueryRowContext(ctx, q, userID, strings.TrimSpace(ip), sshUser).
		Scan(&k.IP, &k.SSHUser, &k.Label, &k.PubLine, &k.PrivEnc, &k.CreatedAt, &k.VerifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// SaveAccessKey stores a granted key. ON CONFLICT DO NOTHING plus a re-read: if two requests generate
// a key in parallel both return the same one (otherwise the user would add a line we had already
// forgotten).
func (r *Repo) SaveAccessKey(ctx context.Context, userID string, k *accessKey) (*accessKey, error) {
	const q = `INSERT INTO server_access_keys (user_id, server_ip, ssh_user, label, pub_line, priv_enc)
	           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (user_id, server_ip, ssh_user) DO NOTHING`
	if _, err := r.db.ExecContext(ctx, q, userID, k.IP, k.SSHUser, k.Label, k.PubLine, k.PrivEnc); err != nil {
		return nil, err
	}
	saved, err := r.AccessKey(ctx, userID, k.IP, k.SSHUser)
	if err != nil {
		return nil, err
	}
	if saved == nil {
		return nil, errors.New("access key vanished after insert")
	}
	return saved, nil
}

// MarkAccessVerified records that we really got in on the key (the first time sets the date).
func (r *Repo) MarkAccessVerified(ctx context.Context, userID, ip, sshUser string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE server_access_keys SET verified_at=COALESCE(verified_at, NOW())
		 WHERE user_id=$1 AND server_ip=$2 AND ssh_user=$3`, userID, strings.TrimSpace(ip), sshUser)
	return err
}

func (r *Repo) DeleteAccessKey(ctx context.Context, userID, ip, sshUser string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM server_access_keys WHERE user_id=$1 AND server_ip=$2 AND ssh_user=$3`,
		userID, strings.TrimSpace(ip), sshUser)
	return err
}

func (r *Repo) ListAccessKeys(ctx context.Context, userID string) ([]accessKey, error) {
	const q = `SELECT server_ip, ssh_user, label, pub_line, priv_enc, created_at, verified_at
	           FROM server_access_keys WHERE user_id=$1 ORDER BY created_at`
	rows, err := r.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []accessKey
	for rows.Next() {
		var k accessKey
		if err := rows.Scan(&k.IP, &k.SSHUser, &k.Label, &k.PubLine, &k.PrivEnc, &k.CreatedAt, &k.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CountDeploymentsOn counts the user's projects living on a server (excludeID: skip this one).
func (r *Repo) CountDeploymentsOn(ctx context.Context, userID, ip, excludeID string) int {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM deployments WHERE user_id=$1 AND server_ip=$2 AND ($3='' OR id<>$3)`,
		userID, strings.TrimSpace(ip), excludeID).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// DeploymentTarget returns the server holding our key for a particular deploy.
type DeploymentTarget struct {
	IP      string
	SSHUser string
	KeyEnc  string
}

// DeploymentAccessTargets returns servers where we hold a deploy key (one per server+ssh-user pair).
// Needed to show and revoke access that was granted before the new scheme.
func (r *Repo) DeploymentAccessTargets(ctx context.Context, userID string) []DeploymentTarget {
	const q = `SELECT DISTINCT ON (server_ip, ssh_user) server_ip, ssh_user, ssh_key_enc
	           FROM deployments
	           WHERE user_id=$1 AND ssh_key_enc IS NOT NULL AND ssh_key_enc <> ''
	           ORDER BY server_ip, ssh_user, created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []DeploymentTarget
	for rows.Next() {
		var t DeploymentTarget
		if err := rows.Scan(&t.IP, &t.SSHUser, &t.KeyEnc); err != nil {
			return out
		}
		out = append(out, t)
	}
	return out
}

// ClearDeploymentKeys forgets the project keys on a server (access is revoked, we cannot get in).
func (r *Repo) ClearDeploymentKeys(ctx context.Context, userID, ip, sshUser string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE deployments SET ssh_key_enc='', updated_at=NOW()
		 WHERE user_id=$1 AND server_ip=$2 AND ssh_user=$3`, userID, strings.TrimSpace(ip), sshUser)
	return err
}

// ── servers the user can already deploy to ───────────────────────────────────

// ServerOption is a server in the "where to deploy" list. Access is there, no need to grant it twice.
type ServerOption struct {
	IP       string `json:"ip"`
	SSHUser  string `json:"ssh_user"`
	Name     string `json:"name"`     // кастомное имя сервера, если задавал
	Projects int    `json:"projects"` // сколько проектов там уже живёт
	TeamID   string `json:"team_id"`  // сервер живёт под этой командой: её и надо выбрать на шаге «Проект»
	Ready    bool   `json:"ready"`    // ключ на месте: шаг выдачи доступа можно пропустить
	Shared   bool   `json:"shared"`   // доступ пришёл от проекта команды, а не выдан лично
}

// Servers lists where the user can deploy right now without granting access again. Servers hosting a
// team project count as theirs too: since they can redeploy it, the key is available to them anyway,
// so asking for a second one is pointless.
// teamID is where the user is about to deploy: a team server counts as ready only for projects of THAT
// team, otherwise the UI would promise access that will not be there at deploy time.
func (s *Service) Servers(ctx context.Context, userID, teamID string) []ServerOption {
	seen := map[string]*ServerOption{}
	add := func(ip, sshUser, name, teamID string, ready, shared bool) {
		k := sshUser + "@" + ip
		if cur, ok := seen[k]; ok {
			cur.Ready = cur.Ready || ready
			if name != "" {
				cur.Name = name
			}
			if cur.TeamID == "" {
				cur.TeamID = teamID
			}
			return
		}
		seen[k] = &ServerOption{IP: ip, SSHUser: sshUser, Name: name, TeamID: teamID, Ready: ready, Shared: shared}
	}
	for _, k := range s.ListAccess(ctx, userID) {
		add(k.ServerIP, k.SSHUser, "", "", true, false)
	}
	// Servers of the projects the user can see (own and team ones): one query instead of getFull per
	// project, otherwise the deploy page would hit the database dozens of times.
	var teamIDs []string
	if s.teams != nil {
		teamIDs, _ = s.teams.TeamIDsOf(ctx, userID)
	}
	for _, r := range s.repo.VisibleServers(ctx, userID, teamIDs) {
		ready := r.HasKey && (r.TeamID == "" || r.TeamID == teamID)
		add(r.IP, r.SSHUser, r.Name, r.TeamID, ready, r.Shared)
	}
	out := make([]ServerOption, 0, len(seen))
	for _, v := range seen {
		v.Projects = s.repo.CountDeploymentsOn(ctx, userID, v.IP, "")
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Projects != out[j].Projects {
			return out[i].Projects > out[j].Projects
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// ServerRow is a server taken from the projects visible to the user (for the "where to deploy" list).
type ServerRow struct {
	IP      string
	SSHUser string
	Name    string
	TeamID  string // непусто = проект командный, ключ работает только внутри этой команды
	HasKey  bool   // на проекте сохранён ключ → зайти сможем
	Shared  bool   // проект командный (ключ общий, а не выданный лично)
}

// VisibleServers returns servers of the user's and their teams' projects, one row per server+ssh-user.
func (r *Repo) VisibleServers(ctx context.Context, userID string, teamIDs []string) []ServerRow {
	q := `SELECT DISTINCT ON (d.server_ip, d.ssh_user)
	              d.server_ip, d.ssh_user, COALESCE(sl.name,''),
	              (d.ssh_key_enc IS NOT NULL AND d.ssh_key_enc <> ''), COALESCE(d.team_id, '')
	       FROM deployments d
	       LEFT JOIN server_labels sl ON sl.user_id=$1 AND sl.server_ip=d.server_ip
	       WHERE ((d.user_id=$1 AND d.team_id IS NULL)`
	args := []any{userID}
	for i, tid := range teamIDs {
		q += fmt.Sprintf(" OR d.team_id=$%d", i+2)
		args = append(args, tid)
	}
	q += `) AND d.status <> 'failed'
	       ORDER BY d.server_ip, d.ssh_user, d.created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ServerRow
	for rows.Next() {
		var v ServerRow
		if err := rows.Scan(&v.IP, &v.SSHUser, &v.Name, &v.HasKey, &v.TeamID); err != nil {
			return out
		}
		out = append(out, v)
	}
	return out
}

// sharedKeyPEM is the key of a team project on this server. It lets a member deploy TEAM projects to
// a team server without granting access again.
//
// The key stays strictly inside the team: a personal project cannot be deployed with it to someone
// else's server. Otherwise a member could join a team once, create a personal project there and keep a
// working key to a stranger's server forever, even after leaving the team.
func (s *Service) sharedKeyPEM(ctx context.Context, userID, teamID, ip, sshUser string) string {
	if teamID == "" {
		return ""
	}
	for _, id := range s.repo.DeploymentIDsOn(ctx, ip, sshUser) {
		dep, keyEnc, err := s.repo.getFull(ctx, id)
		if err != nil || keyEnc == "" {
			continue
		}
		if dep.TeamID != teamID || !s.canAccess(ctx, dep, userID) {
			continue
		}
		if key, de := s.decryptKey(keyEnc); de == nil {
			return key
		}
	}
	return ""
}

// DeploymentIDsOn lists projects on this server (any owner) that have a stored key.
// The right to use the key is checked by the caller through canAccess.
func (r *Repo) DeploymentIDsOn(ctx context.Context, ip, sshUser string) []string {
	const q = `SELECT id FROM deployments
	           WHERE server_ip=$1 AND ssh_user=$2 AND ssh_key_enc IS NOT NULL AND ssh_key_enc <> ''
	           ORDER BY created_at DESC LIMIT 20`
	rows, err := r.db.QueryContext(ctx, q, strings.TrimSpace(ip), sshUser)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return out
		}
		out = append(out, id)
	}
	return out
}

// ── how many projects are in use ─────────────────────────────────────────────

// Usage counts used projects for display next to the plan. The personal limit is spent ONLY by personal
// projects, team ones count against their own team's limit (the same way Start checks it).
// We count with the same condition as the limiter, otherwise the user sees one number and hits another.
type Usage struct {
	Personal int `json:"personal"` // мои личные проекты (тратят мой тариф)
	Team     int `json:"team"`     // проекты команд, которые я вижу (тратят тариф команды)
}

func (s *Service) Usage(ctx context.Context, userID string) Usage {
	var u Usage
	if n, err := s.repo.CountActiveByUser(ctx, userID); err == nil {
		u.Personal = n
	}
	if s.teams == nil {
		return u
	}
	teamIDs, err := s.teams.TeamIDsOf(ctx, userID)
	if err != nil {
		return u
	}
	for _, tid := range teamIDs {
		if n, err := s.repo.CountActiveByTeam(ctx, tid); err == nil {
			u.Team += n
		}
	}
	return u
}
