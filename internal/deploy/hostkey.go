package deploy

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// Host key verification (trust on first use): the first connection records the server's
// fingerprint and every later one is checked against it. On a mismatch the connection is dropped
// BEFORE authentication, so no password and no token reach that server. The pin lives in
// server_host_keys keyed by user and IP: one server means one fingerprint for all of that user's
// projects.
//
// The owner comes from dep.UserID (the record owner), not from the acting user. Otherwise a team
// member who opened the logs would pin a second row under their own name.

// All three wrappers return (connection, host key error, ordinary error). They are separate
// because every caller has its own wording for "could not connect", while the wording for a
// swapped key is shared and carries instructions.

// dialPasswordPinned is the first deploy: a password plus verifying or recording the host key.
func dialPasswordPinned(ctx context.Context, repo *Repo, ownerID, ip, user, password string) (*SSH, *DeployError, error) {
	return dialPinned(ctx, repo, ownerID, ip, true, func(pin *HostPin) (*SSH, error) {
		return DialPassword(ip, user, password, pin)
	})
}

// dialKeyPinned connects with the stored key (redeploy, rollback, logs, stats, .env, VPN).
func dialKeyPinned(ctx context.Context, repo *Repo, ownerID, ip, user, keyPEM string) (*SSH, *DeployError, error) {
	return dialPinned(ctx, repo, ownerID, ip, true, func(pin *HostPin) (*SSH, error) {
		return DialKey(ip, user, keyPEM, pin)
	})
}

// dialKeyVerifyOnly is for BACKGROUND jobs: verification only. An unknown server is skipped, so
// the monitor never pins a key behind the user's back or eats the window after a reset.
func dialKeyVerifyOnly(ctx context.Context, repo *Repo, ownerID, ip, user, keyPEM string) (*SSH, *DeployError, error) {
	return dialPinned(ctx, repo, ownerID, ip, false, func(pin *HostPin) (*SSH, error) {
		return DialKey(ip, user, keyPEM, pin)
	})
}

// dialPinned is the shared part: read the pin, connect, and record it on first acquaintance.
func dialPinned(ctx context.Context, repo *Repo, ownerID, ip string, allowTOFU bool,
	do func(*HostPin) (*SSH, error)) (*SSH, *DeployError, error) {

	var fp, keyType string
	var known bool
	if repo != nil {
		fp, keyType, known = repo.HostPin(ctx, ownerID, ip)
	}
	pin := &HostPin{Expected: fp, KeyType: keyType, AllowTOFU: allowTOFU && !known}

	sshc, err := do(pin)
	if err != nil {
		return nil, hostKeyError(err, ip), err
	}
	if repo == nil {
		return sshc, nil, nil
	}

	pctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if known {
		repo.TouchHostPin(pctx, ownerID, ip)
		return sshc, nil, nil
	}
	// Record ONLY after authentication succeeds: the callback fires before it, and pinning from
	// there would record a stranger's key when the user mistypes the IP.
	stored, terr := repo.TrustHostPin(pctx, ownerID, ip, pin.SeenFP, pin.SeenType, pin.SeenPub)
	if terr == nil && stored != "" && stored != pin.SeenFP {
		// A parallel first connection to the same IP saw a DIFFERENT key. That is no longer TOFU.
		sshc.Close()
		de := errHostKeyMismatch(ip, stored, pin.SeenFP)
		return nil, de, de
	}
	return sshc, nil, nil
}

// hostKeyError turns a connection failure into a user-facing error when it is about the host key.
// nil means an ordinary network or password failure, which the caller explains itself.
func hostKeyError(err error, ip string) *DeployError {
	var mismatch *HostKeyMismatchError
	if errors.As(err, &mismatch) {
		return errHostKeyMismatch(ip, mismatch.Expected, mismatch.Got)
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		return derr("host_key_unknown",
			"Сервер "+ip+" нам ещё не знаком.",
			"Это фоновая проверка, она не запоминает ключи сервера. Нажми «Передеплоить» один раз, и отпечаток запомнится.")
	}
	var negotiation *ssh.AlgorithmNegotiationError
	if errors.As(err, &negotiation) && negotiation.What == "host key" {
		return derr("host_key_gone",
			"Сервер "+ip+" больше не предъявляет SSH-ключ того типа, который мы запомнили.",
			"Похоже, на сервере пересоздали ключи хоста. Если это делал ты — открой карточку сервера на дашборде и нажми «Сервер пересоздан». Если нет — сначала разберись, кто трогал сервер.")
	}
	return nil
}

// errHostKeyMismatch is the wording for a server answering with a different key. The user needs
// both fingerprints, to compare against the provider console, and both scenarios: they rebuilt the
// server themselves, or they did not.
func errHostKeyMismatch(ip, expected, got string) *DeployError {
	return derr("host_key_mismatch",
		"Сервер "+ip+" предъявил ДРУГОЙ SSH-ключ, чем при первом подключении. Соединение разорвано, на сервере ничего не выполнялось.",
		"Запомнили: "+expected+"\n"+
			"Сервер отвечает: "+got+"\n\n"+
			"Если ты пересоздавал сервер, переустанавливал ОС или переезжал к другому провайдеру, это нормально: открой карточку сервера на дашборде и нажми «Сервер пересоздан».\n"+
			"Если ничего такого не делал, не подтверждай: возможно, кто-то вклинился в соединение. Сверь отпечаток в консоли провайдера командой ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
}
