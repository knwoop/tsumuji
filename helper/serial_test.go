package main

import (
	"bufio"
	"io"
	"log/slog"
	"testing"
)

// duplex glues a reader and a writer into one io.ReadWriter.
type duplex struct {
	io.Reader
	io.Writer
}

func TestServeLoopContinuesAfterRefusal(t *testing.T) {
	devToHelperR, devToHelperW := io.Pipe()
	helperToDevR, helperToDevW := io.Pipe()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	done := make(chan error, 1)
	go func() {
		done <- ServeLoop(duplex{devToHelperR, helperToDevW}, plainHandler("hi"), logger)
	}()

	go func() {
		io.WriteString(devToHelperW, "garbage\n")                                          // ignored, no reply
		io.WriteString(devToHelperW, "EV 00 00\n")                                         // malformed, no reply
		io.WriteString(devToHelperW, "EV\n")                                               // served
		io.WriteString(devToHelperW, "EV "+hexZeros(NonceSize)+" "+hexZeros(MACSize)+"\n") // refused with ERR
		io.WriteString(devToHelperW, "EV\n")                                               // served again
		devToHelperW.Close()
	}()

	r := bufio.NewReader(helperToDevR)
	want := []string{"PW hi\n", "ERR\n", "PW hi\n"}
	for _, w := range want {
		got, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if got != w {
			t.Errorf("reply %q, want %q", got, w)
		}
	}
	if err := <-done; err != io.EOF {
		t.Errorf("ServeLoop returned %v, want io.EOF", err)
	}
}

func hexZeros(n int) string {
	b := make([]byte, 2*n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

func TestServeLoopDropsOversizedLine(t *testing.T) {
	devToHelperR, devToHelperW := io.Pipe()
	helperToDevR, helperToDevW := io.Pipe()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	go ServeLoop(duplex{devToHelperR, helperToDevW}, plainHandler("hi"), logger)
	go func() {
		// An "EV" line padded far past the limit must be dropped, not served
		// and not allowed to grow the buffer.
		io.WriteString(devToHelperW, "EV "+hexZeros(10*MaxRequestLine)+"\n")
		io.WriteString(devToHelperW, "EV\n")
		devToHelperW.Close()
	}()

	got, err := bufio.NewReader(helperToDevR).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if got != "PW hi\n" {
		t.Errorf("first reply %q, want the reply to the second (valid) line", got)
	}
}
