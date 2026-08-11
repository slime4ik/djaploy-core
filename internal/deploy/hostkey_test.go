package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is an in-process SSH server: it presents its host key and accepts any password.
// It exists so host key checking can be tested without a live VPS.
func testSSHServer(t *testing.T) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "test server")
				}
				sc.Close()
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func dialTest(addr string, pin *HostPin) (*SSH, error) {
	host, _, _ := net.SplitHostPort(addr)
	return dialAddr(addr, host, "root", pin, ssh.Password("x"))
}

// Unknown server: we connect and record the fingerprint, in the same format as ssh-keygen -lf.
func TestHostKeyTOFURecordsFingerprint(t *testing.T) {
	addr, hostKey := testSSHServer(t)
	pin := &HostPin{AllowTOFU: true}

	sshc, err := dialTest(addr, pin)
	if err != nil {
		t.Fatalf("the first connection must succeed: %v", err)
	}
	defer sshc.Close()

	want := ssh.FingerprintSHA256(hostKey)
	if pin.SeenFP != want {
		t.Fatalf("fingerprint: got %q, want %q", pin.SeenFP, want)
	}
	if !strings.HasPrefix(pin.SeenFP, "SHA256:") {
		t.Fatalf("fingerprint must be in ssh-keygen -lf format, got %q", pin.SeenFP)
	}
	if pin.SeenType != ssh.KeyAlgoED25519 {
		t.Fatalf("key type: got %q", pin.SeenType)
	}
	if !strings.HasPrefix(pin.SeenPub, "ssh-ed25519 ") {
		t.Fatalf("authorized_keys line: got %q", pin.SeenPub)
	}
}

// The pinned key matches, so the connection goes through quietly.
func TestHostKeyPinnedMatches(t *testing.T) {
	addr, hostKey := testSSHServer(t)
	pin := &HostPin{Expected: ssh.FingerprintSHA256(hostKey), KeyType: hostKey.Type()}

	sshc, err := dialTest(addr, pin)
	if err != nil {
		t.Fatalf("a matching key must be accepted: %v", err)
	}
	sshc.Close()
}

// The key was swapped: no connection, and the error is typed so errors.As in hostKeyError catches
// it. If x/crypto ever stops wrapping with %w, the user would get a generic "could not connect"
// instead of the instructions, which is exactly what this test guards.
func TestHostKeyMismatchIsTyped(t *testing.T) {
	addr, _ := testSSHServer(t)
	pin := &HostPin{
		Expected: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyType:  ssh.KeyAlgoED25519,
	}

	sshc, err := dialTest(addr, pin)
	if err == nil {
		sshc.Close()
		t.Fatal("connecting to a foreign host key must fail")
	}
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected HostKeyMismatchError, got %T: %v", err, err)
	}
	if mismatch.Got != pin.SeenFP || mismatch.Expected != pin.Expected {
		t.Fatalf("the error must carry both fingerprints: %+v", mismatch)
	}

	de := hostKeyError(err, "203.0.113.10")
	if de == nil || de.Code != "host_key_mismatch" {
		t.Fatalf("expected DeployError host_key_mismatch, got %+v", de)
	}
	for _, want := range []string{mismatch.Expected, mismatch.Got, "Сервер пересоздан"} {
		if !strings.Contains(de.Message+de.Hint, want) {
			t.Errorf("the error text is missing %q:\n%s\n%s", want, de.Message, de.Hint)
		}
	}
}

// A background job may not pin a key, so an unknown server is refused.
func TestHostKeyVerifyOnlyRefusesUnknown(t *testing.T) {
	addr, _ := testSSHServer(t)

	sshc, err := dialTest(addr, &HostPin{AllowTOFU: false})
	if err == nil {
		sshc.Close()
		t.Fatal("a background check must not connect to an unknown server")
	}
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("expected ErrHostKeyUnknown, got %v", err)
	}
	if de := hostKeyError(err, "203.0.113.10"); de == nil || de.Code != "host_key_unknown" {
		t.Fatalf("expected DeployError host_key_unknown, got %+v", de)
	}
}

// An ordinary network failure must not be passed off as a host key problem.
func TestHostKeyErrorIgnoresOrdinaryFailures(t *testing.T) {
	if de := hostKeyError(errors.New("dial tcp: connection refused"), "203.0.113.10"); de != nil {
		t.Fatalf("expected nil for an ordinary error, got %+v", de)
	}
}

// The algorithm list is narrowed to the pinned type, otherwise a server with both ed25519 and rsa
// may present the key we did not record and we would call it a swap.
func TestHostKeyAlgos(t *testing.T) {
	if got := (&HostPin{}).algos(); got != nil {
		t.Fatalf("an unknown server must not be constrained, got %v", got)
	}
	if got := (&HostPin{KeyType: ssh.KeyAlgoED25519}).algos(); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("ed25519: got %v", got)
	}
	got := (&HostPin{KeyType: ssh.KeyAlgoRSA}).algos()
	if len(got) != 3 {
		t.Fatalf("rsa is offered under three algorithm names, got %v", got)
	}
}
