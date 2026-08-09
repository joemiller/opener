package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestShouldForward(t *testing.T) {
	tt := []struct {
		name     string
		rawURL   string
		wantPort string
		wantOK   bool
	}{
		// Direct localhost URLs
		{
			name:     "direct localhost with port",
			rawURL:   "http://localhost:12345/callback",
			wantPort: "12345",
			wantOK:   true,
		},
		{
			name:     "direct 127.0.0.1 with port",
			rawURL:   "http://127.0.0.1:54321/auth",
			wantPort: "54321",
			wantOK:   true,
		},
		{
			name:     "direct IPv6 loopback with port",
			rawURL:   "http://[::1]:9999/cb",
			wantPort: "9999",
			wantOK:   true,
		},
		// Query param extraction
		{
			name:     "redirect_uri in query",
			rawURL:   "https://login.microsoftonline.com/tenant/oauth2?redirect_uri=http%3A%2F%2Flocalhost%3A38947&client_id=foo",
			wantPort: "38947",
			wantOK:   true,
		},
		{
			name:     "callback in query 127.0.0.1",
			rawURL:   "https://accounts.google.com/o/oauth2?callback=http%3A%2F%2F127.0.0.1%3A12345%2Fcb",
			wantPort: "12345",
			wantOK:   true,
		},
		{
			name:     "azure cli oauth",
			rawURL:   "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=xxx&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A38947&scope=https%3A%2F%2Fmanagement.core.windows.net%2F%2F.default+offline_access+openid+profile&state=xxx&code_challenge=xxx&code_challenge_method=S256&nonce=xxx&client_info=1&claims=%7B%22access_token%22%3A+%7B%22xms_cc%22%3A+%7B%22values%22%3A+%5B%22CP1%22%5D%7D%7D%7D&prompt=select_account",
			wantPort: "38947",
			wantOK:   true,
		},
		{
			name:     "gcloud cli oauth",
			rawURL:   "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=32555940559.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fappengine.admin+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fsqlservice.login+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Faccounts.reauth&state=xxx&access_type=offline&code_challenge=xxx&code_challenge_method=S256",
			wantPort: "8085",
			wantOK:   true,
		},
		{
			name:     "first of multiple localhost params wins",
			rawURL:   "https://example.com/?foo=http%3A%2F%2Flocalhost%3A9999&bar=http%3A%2F%2Flocalhost%3A8888",
			wantPort: "9999",
			wantOK:   true,
		},
		// Should not forward
		{
			name:     "non-localhost URL no localhost in params",
			rawURL:   "https://accounts.google.com/o/oauth2",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "redirect_uri is not localhost",
			rawURL:   "https://example.com/?redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "localhost without port implies 80",
			rawURL:   "https://example.com/?redirect_uri=http%3A%2F%2Flocalhost%2Fpath",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "direct localhost path no port",
			rawURL:   "http://localhost/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "standard port 443 skip",
			rawURL:   "http://localhost:443/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "standard port 80 skip",
			rawURL:   "http://localhost:80/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "non-numeric port rejected",
			rawURL:   "http://localhost:abc/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "port 0 rejected",
			rawURL:   "http://localhost:0/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "port exceeding 65535 rejected",
			rawURL:   "http://localhost:99999/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "negative port rejected",
			rawURL:   "http://localhost:-1/path",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "malformed URL",
			rawURL:   "not-a-url",
			wantPort: "",
			wantOK:   false,
		},
		{
			name:     "empty string",
			rawURL:   "",
			wantPort: "",
			wantOK:   false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			port, ok := shouldForward(tc.rawURL)
			if ok != tc.wantOK || port != tc.wantPort {
				t.Errorf("shouldForward(%q) = %q, %v; want %q, %v", tc.rawURL, port, ok, tc.wantPort, tc.wantOK)
			}
		})
	}
}

func TestForwardTrackerCleanup(t *testing.T) {
	tt := []struct {
		name           string
		cancelCmd      string // "true" (exit 0) or "false" (exit 1)
		expiredRemoved bool
	}{
		{"cancel succeeds", "true", true},
		{"cancel fails", "false", false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ft := newForwardTracker("/unused", 100*time.Millisecond, io.Discard)
			ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
				return exec.Command(tc.cancelCmd)
			}
			ft.mu.Lock()
			ft.active["11111"] = time.Now().Add(-200 * time.Millisecond) // expired
			ft.active["22222"] = time.Now().Add(-50 * time.Millisecond)  // not expired
			ft.mu.Unlock()

			ft.cleanup()

			ft.mu.Lock()
			defer ft.mu.Unlock()
			_, expiredExists := ft.active["11111"]
			if tc.expiredRemoved && expiredExists {
				t.Error("expired entry 11111 should be removed after successful cancel")
			}
			if !tc.expiredRemoved && !expiredExists {
				t.Error("expired entry 11111 should remain when ssh cancel fails")
			}
			if _, ok := ft.active["22222"]; !ok {
				t.Error("non-expired entry 22222 should remain")
			}
		})
	}
}

func TestForwardTrackerRunExitsOnContextCancel(t *testing.T) {
	ft := newForwardTracker("/nonexistent/socket", time.Minute, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ft.run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// run() exited
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after context cancel")
	}
}

func TestForwardTrackerForwardLogsError(t *testing.T) {
	var buf bytes.Buffer
	ft := newForwardTracker("/nonexistent/control/socket", time.Minute, &buf)
	ft.forward("", "12345")
	if !strings.Contains(buf.String(), "opener: ssh forward -L") {
		t.Errorf("expected forward error log, got: %s", buf.String())
	}
}

func TestDirectoryForwardTrackerForwardFansOut(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // bind on short basenames; the socket path has a length limit
	for _, name := range []string{"host-a", "host-b"} {
		ln, err := net.Listen("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}
	if err := os.WriteFile(filepath.Join(dir, "not-a-socket"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	forwarded := map[string][]string{} // socket -> "op:port"
	d := newDirectoryForwardTracker(dir, time.Minute, io.Discard)
	d.newTracker = func(socket string) *forwardTracker {
		ft := newForwardTracker(socket, time.Minute, io.Discard)
		ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
			mu.Lock()
			forwarded[socket] = append(forwarded[socket], op+":"+port)
			mu.Unlock()
			return exec.Command("true")
		}
		return ft
	}

	d.forward("", "12345")

	mu.Lock()
	defer mu.Unlock()
	if len(forwarded) != 2 {
		t.Fatalf("expected 2 sockets forwarded, got %d: %v", len(forwarded), forwarded)
	}
	for _, name := range []string{"host-a", "host-b"} {
		socket := filepath.Join(dir, name)
		if got := forwarded[socket]; len(got) != 1 || got[0] != "forward:12345" {
			t.Errorf("socket %s: expected [forward:12345], got %v", socket, got)
		}
	}
}

func TestDirectoryForwardTrackerCleanupReapsVanishedSockets(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // bind on a short basename; the socket path has a length limit
	socket := filepath.Join(dir, "host-a")
	ln, err := net.Listen("unix", "host-a")
	if err != nil {
		t.Fatal(err)
	}

	d := newDirectoryForwardTracker(dir, time.Minute, io.Discard)
	d.newTracker = func(socket string) *forwardTracker {
		ft := newForwardTracker(socket, time.Minute, io.Discard)
		ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
			return exec.Command("true")
		}
		return ft
	}

	d.forward("", "12345")
	d.mu.Lock()
	_, ok := d.trackers[socket]
	d.mu.Unlock()
	if !ok {
		t.Fatal("expected a tracker for host-a after forward")
	}

	ln.Close() // closing a unix listener unlinks the socket file
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("expected socket to be gone after Close, stat err = %v", err)
	}

	d.cleanup()

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.trackers[socket]; ok {
		t.Error("expected tracker for vanished socket to be reaped")
	}
}

func TestForwardTrackerForwardDedup(t *testing.T) {
	var calls atomic.Int32
	ft := newForwardTracker("/unused", time.Minute, io.Discard)
	ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
		calls.Add(1)
		return exec.Command("true")
	}

	ft.forward("", "12345")
	ft.forward("", "12345")

	if n := calls.Load(); n != 1 {
		t.Errorf("expected ssh to be called once, got %d", n)
	}
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if _, ok := ft.active["12345"]; !ok {
		t.Error("port should remain in active map")
	}
}

func TestParseMessage(t *testing.T) {
	tt := []struct {
		name    string
		line    string
		wantID  string
		wantURL string
	}{
		{"bare URL", "http://localhost:12345/cb", "", "http://localhost:12345/cb"},
		{"%C hash prefix", "656ce8589523b0fcef8cf0dd077da245d153de5b http://localhost:12345/cb", "656ce8589523b0fcef8cf0dd077da245d153de5b", "http://localhost:12345/cb"},
		{"hostname-style id", "my-host.example.org https://example.com/?redirect_uri=http%3A%2F%2Flocalhost%3A38947", "my-host.example.org", "https://example.com/?redirect_uri=http%3A%2F%2Flocalhost%3A38947"},
		{"id with extra spaces", "abc123  http://localhost:8085/", "abc123", "http://localhost:8085/"},
		{"URL with query ampersands no space", "https://example.com/?a=1&b=2", "", "https://example.com/?a=1&b=2"},
		{"space but first token is URL", "http://localhost:1 has space", "", "http://localhost:1 has space"},
		{"path traversal rejected as id", "../evil http://localhost:1", "", "../evil http://localhost:1"},
		{"empty", "", "", ""},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			c, rawURL := parseMessage(tc.line)
			if c != tc.wantID || rawURL != tc.wantURL {
				t.Errorf("parseMessage(%q) = %q, %q; want %q, %q", tc.line, c, rawURL, tc.wantID, tc.wantURL)
			}
		})
	}
}

func TestSocketMatchesID(t *testing.T) {
	tt := []struct {
		socket string
		c      string
		want   bool
	}{
		{"/home/me/.ssh/control/abc123", "abc123", true},
		{"/home/me/.ssh/control/abc123.sock", "abc123", true},
		{"/home/me/.ssh/control/abc123.sock", "abc123.sock", true},
		{"/home/me/.ssh/control/abc123", "def456", false},
		{"/home/me/.ssh/control/abc12345", "abc123", false},
		{"/home/me/.ssh/control/me@host:22", "me@host:22", true},
	}
	for _, tc := range tt {
		if got := socketMatchesID(tc.socket, tc.c); got != tc.want {
			t.Errorf("socketMatchesID(%q, %q) = %v; want %v", tc.socket, tc.c, got, tc.want)
		}
	}
}

func TestForwardTrackerForwardSkipsMismatchedID(t *testing.T) {
	var calls atomic.Int32
	ft := newForwardTracker("/control/host-a", time.Minute, io.Discard)
	ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
		calls.Add(1)
		return exec.Command("true")
	}

	ft.forward("host-b", "12345") // mismatched id: must not exec ssh
	if n := calls.Load(); n != 0 {
		t.Errorf("expected ssh not to be called for mismatched id, got %d calls", n)
	}
	ft.mu.Lock()
	_, ok := ft.active["12345"]
	ft.mu.Unlock()
	if ok {
		t.Error("port should not be marked active for mismatched id")
	}

	ft.forward("host-a", "12345") // matching id
	if n := calls.Load(); n != 1 {
		t.Errorf("expected ssh to be called once for matching id, got %d", n)
	}
}

func TestDirectoryForwardTrackerForwardTargetsMatchingSocket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // bind on short basenames; the socket path has a length limit
	for _, name := range []string{"hash-a.sock", "hash-b.sock"} {
		ln, err := net.Listen("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}

	var mu sync.Mutex
	forwarded := map[string][]string{} // socket -> ports
	d := newDirectoryForwardTracker(dir, time.Minute, io.Discard)
	d.newTracker = func(socket string) *forwardTracker {
		ft := newForwardTracker(socket, time.Minute, io.Discard)
		ft.sshControlCmdFunc = func(ctx context.Context, op, port string) *exec.Cmd {
			mu.Lock()
			forwarded[socket] = append(forwarded[socket], port)
			mu.Unlock()
			return exec.Command("true")
		}
		return ft
	}

	// Targeted forward: only the matching socket gets the port.
	d.forward("hash-a", "12345")

	mu.Lock()
	if got := forwarded[filepath.Join(dir, "hash-a.sock")]; len(got) != 1 || got[0] != "12345" {
		t.Errorf("expected hash-a.sock to forward 12345, got %v", got)
	}
	if got := forwarded[filepath.Join(dir, "hash-b.sock")]; len(got) != 0 {
		t.Errorf("expected hash-b.sock to forward nothing, got %v", got)
	}
	mu.Unlock()

	// Unknown id: nothing is forwarded.
	var buf bytes.Buffer
	d.errOut = &buf
	d.forward("hash-c", "22222")
	mu.Lock()
	for socket, got := range forwarded {
		for _, p := range got {
			if p == "22222" {
				t.Errorf("socket %s unexpectedly forwarded unknown-id port 22222", socket)
			}
		}
	}
	mu.Unlock()
	if !strings.Contains(buf.String(), "no control socket") {
		t.Errorf("expected a 'no control socket' log, got: %s", buf.String())
	}
}
