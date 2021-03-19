package elf

import (
	"github.com/saferwall/binstream"
)

// Parser implements a parsing engine for the ELF file format.
type Parser struct {
	f *binstream.FileStream
}

// New creates a new instance of parser.
func New(filename string) (*Parser, error) {
	fs, err := binstream.NewFileStream(filename)
	if err != nil {
		return nil, err
	}
	p := &Parser{
		f: fs,
	}
	return p, nil
}

// ReadMagicBytes will read the 4 first bytes of the file.
func (p *Parser) ReadMagicBytes() ([]byte, error) {
	magic := make([]byte, 4)
	p.f.Read(magic)
	return magic, nil
}

// CloseFile will close underlying mmap file
func (p *Parser) CloseFile() error {
	return p.f.Close()
}
