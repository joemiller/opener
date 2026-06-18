package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sshForwardTimeout = 3 * time.Second
const cleanupInterval = 10 * time.Second

// forwarder sets up SSH port forwards for loopback ports and periodically
// cleans up expired ones until its context is cancelled.
type forwarder interface {
	forward(port string)
	run(ctx context.Context)
}

// shouldForward parses rawURL and returns a non-standard loopback port if the URL
// (or any query parameter value parsed as a URL) refers to localhost with a
// non-standard port. Query parameters are scanned in the order they appear in
// the raw URL. Returns "", false if no such port is found or on parse errors.
func shouldForward(rawURL string) (port string, ok bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	if p := loopbackPort(u); p != "" {
		return p, true
	}
	// Iterate over the raw query string to preserve parameter order.
	for _, param := range strings.Split(u.RawQuery, "&") {
		_, v, _ := strings.Cut(param, "=")
		v, err := url.QueryUnescape(v)
		if err != nil {
			continue
		}
		sub, err := url.Parse(v)
		if err != nil {
			continue
		}
		if p := loopbackPort(sub); p != "" {
			return p, true
		}
	}
	return "", false
}

// loopbackPort returns the port from u if u's host is loopback and the port is
// present and not 80 or 443. Otherwise returns "".
func loopbackPort(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return ""
	}
	port := u.Port()
	if port == "" || port == "80" || port == "443" {
		return ""
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return port
}

type forwardTracker struct {
	mu                sync.Mutex
	active            map[string]time.Time // port -> last forwarded time
	ttl               time.Duration
	errOut            io.Writer
	sshControlCmdFunc func(ctx context.Context, operation, port string) *exec.Cmd
}

func newForwardTracker(controlSocket string, ttl time.Duration, errOut io.Writer) *forwardTracker {
	return &forwardTracker{
		active: make(map[string]time.Time),
		ttl:    ttl,
		errOut: errOut,
		sshControlCmdFunc: func(ctx context.Context, op, port string) *exec.Cmd {
			return exec.CommandContext(ctx, "ssh", "-S", controlSocket, "-O", op, "-L", port+":localhost:"+port, "none")
		},
	}
}

func (ft *forwardTracker) forward(port string) {
	ft.mu.Lock()
	if _, exists := ft.active[port]; exists {
		ft.active[port] = time.Now()
		ft.mu.Unlock()
		if ft.errOut != nil {
			fmt.Fprintf(ft.errOut, "opener: port %s already forwarded, refreshing TTL\n", port)
		}
		return
	}
	// Mark the port as in-progress to prevent duplicate ssh execs.
	ft.active[port] = time.Now()
	ft.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), sshForwardTimeout)
	defer cancel()
	cmd := ft.sshControlCmdFunc(ctx, "forward", port)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		ft.mu.Lock()
		delete(ft.active, port)
		ft.mu.Unlock()
		if ft.errOut != nil {
			fmt.Fprintf(ft.errOut, "opener: ssh forward -L %s:localhost:%s: %v: %s\n", port, port, err, stderr.String())
		}
		return
	}

	if ft.errOut != nil {
		fmt.Fprintf(ft.errOut, "opener: forwarded -L %s:localhost:%s\n", port, port)
	}
}

func (ft *forwardTracker) cancelForward(port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), sshForwardTimeout)
	defer cancel()
	cmd := ft.sshControlCmdFunc(ctx, "cancel", port)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

func (ft *forwardTracker) cleanup() {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := time.Now()
	for port, ts := range ft.active {
		if now.Sub(ts) <= ft.ttl {
			continue
		}
		err := ft.cancelForward(port)
		if err == nil {
			delete(ft.active, port)
		}
		if ft.errOut != nil {
			if err != nil {
				fmt.Fprintf(ft.errOut, "opener: ssh cancel -L %s:localhost:%s: %v\n", port, port, err)
			} else {
				fmt.Fprintf(ft.errOut, "opener: cancelled forward -L %s:localhost:%s\n", port, port)
			}
		}
	}
}

func (ft *forwardTracker) run(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ft.cleanup()
		}
	}
}

// directoryForwardTracker forwards ports over every UNIX-domain socket that
// appears in a directory. SSH requires one control socket per host, so the
// directory is expected to hold one control socket per connected host. The
// directory is rescanned on every forward and cleanup so sockets may come and
// go as SSH connections are established and torn down.
type directoryForwardTracker struct {
	dir        string
	ttl        time.Duration
	errOut     io.Writer
	newTracker func(socket string) *forwardTracker

	mu       sync.Mutex
	trackers map[string]*forwardTracker // socket path -> tracker
}

func newDirectoryForwardTracker(dir string, ttl time.Duration, errOut io.Writer) *directoryForwardTracker {
	return &directoryForwardTracker{
		dir:      dir,
		ttl:      ttl,
		errOut:   errOut,
		trackers: make(map[string]*forwardTracker),
		newTracker: func(socket string) *forwardTracker {
			return newForwardTracker(socket, ttl, errOut)
		},
	}
}

// sockets returns the paths of every UNIX-domain socket in the directory.
func (d *directoryForwardTracker) sockets() []string {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		if d.errOut != nil {
			fmt.Fprintf(d.errOut, "opener: read control socket directory %s: %v\n", d.dir, err)
		}
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSocket != 0 {
			paths = append(paths, filepath.Join(d.dir, entry.Name()))
		}
	}
	return paths
}

// tracker returns the forwardTracker for socket, creating it on first use.
func (d *directoryForwardTracker) tracker(socket string) *forwardTracker {
	d.mu.Lock()
	defer d.mu.Unlock()
	ft, ok := d.trackers[socket]
	if !ok {
		ft = d.newTracker(socket)
		d.trackers[socket] = ft
	}
	return ft
}

func (d *directoryForwardTracker) forward(port string) {
	var wg sync.WaitGroup
	for _, socket := range d.sockets() {
		ft := d.tracker(socket)
		wg.Add(1)
		go func(ft *forwardTracker) {
			defer wg.Done()
			ft.forward(port)
		}(ft)
	}
	wg.Wait()
}

// cleanup expires stale forwards on each tracker and drops trackers whose
// socket has disappeared. Forwards through a vanished socket die with it.
func (d *directoryForwardTracker) cleanup() {
	present := make(map[string]bool)
	for _, socket := range d.sockets() {
		present[socket] = true
	}

	d.mu.Lock()
	trackers := make(map[string]*forwardTracker, len(d.trackers))
	for socket, ft := range d.trackers {
		if present[socket] {
			trackers[socket] = ft
		} else {
			delete(d.trackers, socket)
		}
	}
	d.mu.Unlock()

	for _, ft := range trackers {
		ft.cleanup()
	}
}

func (d *directoryForwardTracker) run(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

// multiForwarder fans out forward and run calls to several forwarders.
type multiForwarder []forwarder

func (m multiForwarder) forward(port string) {
	var wg sync.WaitGroup
	for _, f := range m {
		wg.Add(1)
		go func(f forwarder) {
			defer wg.Done()
			f.forward(port)
		}(f)
	}
	wg.Wait()
}

func (m multiForwarder) run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range m {
		wg.Add(1)
		go func(f forwarder) {
			defer wg.Done()
			f.run(ctx)
		}(f)
	}
	wg.Wait()
}
