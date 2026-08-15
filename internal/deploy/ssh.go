package deploy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSH struct{ client *ssh.Client }

// HostPin is the host key policy for ONE connection (trust on first use).
//
//	Expected == ""  → unknown server: we accept the key it presents and return it in Seen*.
//	                  The CALLER stores it, and only after authentication succeeds.
//	Expected != ""  → strict comparison; a mismatch gives HostKeyMismatchError and no connection.
//	AllowTOFU=false → an unknown server is refused (background jobs never pin keys).
type HostPin struct {
	Expected  string // "SHA256:…" из server_host_keys.fingerprint
	KeyType   string // тип закреплённого ключа (сужаем HostKeyAlgorithms под него)
	AllowTOFU bool

	// Filled in by the callback: what the server actually presented.
	SeenFP   string
	SeenType string
	SeenPub  string // строка authorized_keys
}

// HostKeyMismatchError means the server presented a different key. No connection was made and
// nothing ran on the server: the callback fires before authentication.
type HostKeyMismatchError struct{ IP, Expected, Got string }

func (e *HostKeyMismatchError) Error() string {
	return "ssh host key mismatch for " + e.IP + ": expected " + e.Expected + ", got " + e.Got
}

// ErrHostKeyUnknown means no key is pinned and this caller is not allowed to pin one.
var ErrHostKeyUnknown = errors.New("ssh: host key not pinned")

// callback verifies the host key. The fingerprint is the same SHA256 that ssh-keygen -lf prints.
func (p *HostPin) callback(ip string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		p.SeenFP, p.SeenType = fp, key.Type()
		p.SeenPub = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

		if p.Expected == "" {
			if !p.AllowTOFU {
				return ErrHostKeyUnknown
			}
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(fp), []byte(p.Expected)) == 1 {
			return nil
		}
		return &HostKeyMismatchError{IP: ip, Expected: p.Expected, Got: fp}
	}
}

// algos narrows the host key algorithms down to the pinned type. Without it a server that has both
// ed25519 and rsa can present a different key than the one we remembered, and we would decide the
// key had been swapped.
func (p *HostPin) algos() []string {
	switch p.KeyType {
	case "":
		return nil // незнакомый сервер: пусть договариваются как обычно
	case ssh.KeyAlgoRSA:
		// the same rsa host key is offered under three algorithm names
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	default:
		return []string{p.KeyType}
	}
}

// DialPassword connects with a password (the first deploy). We offer BOTH password and
// keyboard-interactive: many servers (PAM) accept only keyboard-interactive, and otherwise auth is
// rejected even though the password is right (OpenSSH on a Mac tries both, which is why it works there).
func DialPassword(ip, user, password string, pin *HostPin) (*SSH, error) {
	ki := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		ans := make([]string, len(questions))
		for i := range ans {
			ans[i] = password // на каждый запрос (обычно "Password:") отвечаем паролем
		}
		return ans, nil
	})
	return dial(ip, user, pin, ssh.Password(password), ki)
}

// DialKey connects with our own private key, which is how redeploys and CD run without a password.
func DialKey(ip, user, keyPEM string, pin *HostPin) (*SSH, error) {
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}
	return dial(ip, user, pin, ssh.PublicKeys(signer))
}

func dial(ip, user string, pin *HostPin, auth ...ssh.AuthMethod) (*SSH, error) {
	return dialAddr(net.JoinHostPort(ip, "22"), ip, user, pin, auth...)
}

// dialAddr is the same with an explicit address (dial hardcodes port 22, tests need their own).
func dialAddr(addr, ip, user string, pin *HostPin, auth ...ssh.AuthMethod) (*SSH, error) {
	if pin == nil {
		pin = &HostPin{AllowTOFU: true}
	}
	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              auth,
		HostKeyCallback:   pin.callback(ip),
		HostKeyAlgorithms: pin.algos(),
		Timeout:           15 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &SSH{client: client}, nil
}

func (s *SSH) Close() {
	if s.client != nil {
		s.client.Close()
	}
}

// Run executes a command and STREAMS stdout and stderr into logf, line by line.
func (s *SSH) Run(ctx context.Context, cmd string, logf func(string)) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()

	if err := sess.Start(cmd); err != nil {
		return err
	}

	var wg sync.WaitGroup
	scan := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // длинные строки docker build
		for sc.Scan() {
			logf(sc.Text())
		}
	}
	wg.Add(2)
	go scan(stdout)
	go scan(stderr)

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		wg.Wait()
		return err
	}
}

// WriteFile writes content to path on the server (through stdin into cat, no escaping headaches).
func (s *SSH) WriteFile(path, content, mode string) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(content)
	cmd := fmt.Sprintf("mkdir -p %q && cat > %q && chmod %s %q",
		filepath.Dir(path), path, mode, path)
	return sess.Run(cmd)
}
