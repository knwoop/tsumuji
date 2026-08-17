package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// USB identity the firmware advertises (see tsumuji_keyboard.ino):
// Espressif VID with the ESP32-S3 TinyUSB PID, and a custom product string.
const (
	usbVID     = "303A"
	usbPID     = "1001"
	usbProduct = "tsumuji"
)

// MaxRequestLine bounds one request line. The longest legal request is
// "EV <32 hex> <64 hex>\n" = 101 bytes; anything longer is discarded so a
// misbehaving device cannot make the daemon buffer without limit.
const MaxRequestLine = 256

var (
	ErrDeviceNotFound  = errors.New("no tsumuji device found (is it plugged in?)")
	ErrDeviceAmbiguous = errors.New("more than one tsumuji device found; use --port")
	ErrLineTooLong     = errors.New("request line exceeds MaxRequestLine; discarded")
)

// FindDevicePort returns the serial port of the tsumuji board, matched on
// VID, PID and product string. If explicit is non-empty it is returned as-is.
// It never falls back to an arbitrary port: opening the wrong device would
// block in Read and the real board would go unnoticed.
func FindDevicePort(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return "", err
	}
	var matches []string
	for _, p := range ports {
		if !p.IsUSB {
			continue
		}
		if strings.EqualFold(p.VID, usbVID) && strings.EqualFold(p.PID, usbPID) &&
			strings.Contains(strings.ToLower(p.Product), usbProduct) {
			matches = append(matches, p.Name)
		}
	}
	switch len(matches) {
	case 0:
		return "", ErrDeviceNotFound
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%w: %s", ErrDeviceAmbiguous, strings.Join(matches, ", "))
	}
}

// OpenPort opens the CDC port. Baud rate is irrelevant for USB CDC but must be set.
func OpenPort(name string) (serial.Port, error) {
	p, err := serial.Open(name, &serial.Mode{BaudRate: 115200})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return p, nil
}

// ServeLoop reads request lines from rw and answers them via handler until
// the port errors out. Handler errors are reported through logger and do not
// stop the loop. It returns the terminal I/O error.
func ServeLoop(rw io.ReadWriter, handler Handler, logger *slog.Logger) error {
	r := bufio.NewReaderSize(rw, MaxRequestLine)
	for {
		line, err := readBoundedLine(r)
		if err != nil {
			if errors.Is(err, ErrLineTooLong) {
				logger.Warn("request refused", "err", err)
				continue
			}
			return err
		}
		reply, herr := handler(line)
		if herr != nil {
			logger.Warn("request refused", "err", herr)
		} else {
			logger.Info("request served")
		}
		if reply == "" {
			continue
		}
		if _, err := io.WriteString(rw, reply); err != nil {
			return err
		}
	}
}

// RunForever keeps (re)connecting to the device and serving requests, so the
// helper survives unplug/replug when run under launchd. It only returns when
// ctx is cancelled.
func RunForever(ctx context.Context, portName string, handler Handler, logger *slog.Logger) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := FindDevicePort(portName)
		if err != nil {
			logger.Info("waiting for device", "err", err)
			if !sleepCtx(ctx, 2*time.Second) {
				return ctx.Err()
			}
			continue
		}
		port, err := OpenPort(name)
		if err != nil {
			logger.Warn("open failed", "err", err)
			if !sleepCtx(ctx, 2*time.Second) {
				return ctx.Err()
			}
			continue
		}
		logger.Info("connected", "port", name)
		err = serveUntilDone(ctx, port, handler, logger)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logger.Warn("disconnected", "err", err)
		if !sleepCtx(ctx, time.Second) {
			return ctx.Err()
		}
	}
}

// readBoundedLine reads one newline-terminated line of at most MaxRequestLine
// bytes. Longer lines are consumed and dropped with ErrLineTooLong so the
// stream stays in sync.
func readBoundedLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err == nil {
		return string(line), nil
	}
	if !errors.Is(err, bufio.ErrBufferFull) {
		return "", err
	}
	// Discard the rest of the oversized line.
	for {
		_, err = r.ReadSlice('\n')
		if err == nil {
			return "", ErrLineTooLong
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
}

// serveUntilDone runs ServeLoop on port and closes the port when ctx ends,
// which unblocks the pending Read inside ServeLoop.
func serveUntilDone(ctx context.Context, port serial.Port, handler Handler, logger *slog.Logger) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		port.Close()
	}()
	return ServeLoop(port, handler, logger)
}

// sleepCtx sleeps for d or until ctx is done; returns false if ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
