package elf

// file reader.go was taken from debug/elf as it implements custom utilities to read compressed section data.
import (
	"fmt"
	"io"
	"os"
)

/*
 * ELF reader
 */
type FormatError struct {
	off int64
	msg string
	val interface{}
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v' ", e.val)
	}
	msg += fmt.Sprintf("in record at byte %#x", e.off)
	return msg
}

// seekStart, seekCurrent, seekEnd are copies of
// io.SeekStart, io.SeekCurrent, and io.SeekEnd.
// We can't use the ones from package io because
// we want this code to build with Go 1.4 during
// cmd/dist bootstrap.
const (
	seekStart   int = 0
	seekCurrent int = 1
	seekEnd     int = 2
)

// errorReader returns error from all operations.
type errorReader struct {
	error
}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, r.error
}
func (r errorReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, r.error
}
func (r errorReader) Seek(offset int64, whence int) (int64, error) {
	return 0, r.error
}
func (r errorReader) Close() error {
	return r.error
}

// readSeekerFromReader converts an io.Reader into an io.ReadSeeker.
// In general Seek may not be efficient, but it is optimized for
// common cases such as seeking to the end to find the length of the
// data.
type readSeekerFromReader struct {
	reset  func() (io.Reader, error)
	r      io.Reader
	size   int64
	offset int64
}

func (r *readSeekerFromReader) start() {
	x, err := r.reset()
	if err != nil {
		r.r = errorReader{err}
	} else {
		r.r = x
	}
	r.offset = 0
}
func (r *readSeekerFromReader) Read(p []byte) (n int, err error) {
	if r.r == nil {
		r.start()
	}
	n, err = r.r.Read(p)
	r.offset += int64(n)
	return n, err
}
func (r *readSeekerFromReader) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case seekStart:
		newOffset = offset
	case seekCurrent:
		newOffset = r.offset + offset
	case seekEnd:
		newOffset = r.size + offset
	default:
		return 0, os.ErrInvalid
	}
	switch {
	case newOffset == r.offset:
		return newOffset, nil
	case newOffset < 0, newOffset > r.size:
		return 0, os.ErrInvalid
	case newOffset == 0:
		r.r = nil
	case newOffset == r.size:
		r.r = errorReader{io.EOF}
	default:
		if newOffset < r.offset {
			// Restart at the beginning.
			r.start()
		}
		// Read until we reach offset.
		var buf [512]byte
		for r.offset < newOffset {
			b := buf[:]
			if newOffset-r.offset < int64(len(buf)) {
				b = buf[:newOffset-r.offset]
			}
			if _, err := r.Read(b); err != nil {
				return 0, err
			}
		}
	}
	r.offset = newOffset
	return r.offset, nil
}
