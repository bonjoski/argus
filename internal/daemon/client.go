package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"bonjoski/argus/internal/model"
)

// Client provides an IPC client interface to interact with a resident Argus daemon.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient returns an IPC client connected to the specified socket.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    500 * time.Millisecond,
	}
}

// WithTimeout sets a custom connection and request timeout.
func (c *Client) WithTimeout(d time.Duration) *Client {
	c.timeout = d
	return c
}

// IsRunning checks if the daemon socket exists and is accepting connections.
func (c *Client) IsRunning(ctx context.Context) bool {
	if _, err := os.Stat(c.socketPath); err != nil {
		return false
	}
	return c.Ping(ctx) == nil
}

func (c *Client) send(ctx context.Context, req Request) (*Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to argus daemon socket %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	_ = conn.SetDeadline(deadline)

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode daemon request: %w", err)
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("failed to write request to daemon: %w", err)
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response from daemon: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode daemon response: %w", err)
	}

	if !resp.Success {
		return &resp, errors.New(resp.Error)
	}

	return &resp, nil
}

// Ping checks daemon responsiveness.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.send(ctx, Request{Action: ActionPing})
	if err != nil {
		return fmt.Errorf("daemon ping failed: %w", err)
	}
	return nil
}

// Vet delegates a package vetting evaluation to the resident daemon.
func (c *Client) Vet(ctx context.Context, eco model.Ecosystem, pkgName, version string, noCache bool) (*model.RiskReport, error) {
	req := Request{
		Action:    ActionVet,
		Ecosystem: eco,
		Package:   pkgName,
		Version:   version,
		NoCache:   noCache,
	}

	resp, err := c.send(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("daemon vet request failed: %w", err)
	}

	if resp.Report == nil {
		return nil, errors.New("daemon returned empty vetting report")
	}

	return resp.Report, nil
}

// Stats retrieves the resident daemon's operational metrics.
func (c *Client) Stats(ctx context.Context) (*DaemonStats, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.send(ctx, Request{Action: ActionStats})
	if err != nil {
		return nil, fmt.Errorf("daemon stats request failed: %w", err)
	}

	if resp.Stats == nil {
		return nil, errors.New("daemon returned empty stats")
	}

	return resp.Stats, nil
}

// Shutdown requests the daemon process to exit gracefully.
func (c *Client) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.send(ctx, Request{Action: ActionShutdown})
	if err != nil {
		return fmt.Errorf("daemon shutdown request failed: %w", err)
	}
	return nil
}
