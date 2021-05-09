// Package elf : err.go implements the main error handling code & error strings.
package elf

import "errors"

// ErrNoSymbols is returned by File.Symbols and File.DynamicSymbols
// if there is no such section in the File.
var ErrNoSymbols = errors.New("no symbol section")

// ErrBadELFClass is returned if the ELF class is unknown.
var ErrBadELFClass = errors.New("bad elf class")
