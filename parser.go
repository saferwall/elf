package elf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/saferwall/binstream"
)

// Parser implements a parsing engine for the ELF file format.
type Parser struct {
	fs *binstream.FileStream
	F  *File
}

// New creates a new instance of parser.
func New(filename string) (*Parser, error) {
	fs, err := binstream.NewFileStream(filename)
	if err != nil {
		return nil, err
	}
	p := &Parser{
		fs: fs,
		F:  &File{},
	}
	return p, nil
}

// Parse will parse the entire ELF file.
func (p *Parser) Parse() (*Parser, error) {
	return nil, nil
}

// ParseIdent will parse the identification bytes at the start of the ELF File.
func (p *Parser) ParseIdent() error {

	ident := make([]byte, EI_NIDENT)
	magic := make([]byte, 4)
	// Read the ELF Header E_Ident array.
	// This step helps find out the architecture
	// that the binary targets, as well as OS ABI version
	// and other compilation artefact.
	n, err := p.fs.ReadAt(ident, 0)
	if n != EI_NIDENT || err != nil {
		return err
	}
	copy(magic, ident[:4])
	if n != 16 || string(magic) != ELFMAG {
		return errors.New("bad magic number " + string(magic) + " expected : " + ELFMAG)
	}
	copy(p.F.Ident.Magic[:], magic)
	p.F.Ident.Class = Class(ident[EI_CLASS])
	switch p.F.Ident.Class {
	case ELFCLASS32:
	case ELFCLASS64:
	default:
		return errors.New("bad ELF class")
	}
	p.F.Ident.Data = Data(ident[EI_DATA])
	switch p.F.Ident.Data {
	case ELFDATA2LSB:
		p.F.Ident.ByteOrder = binary.LittleEndian
	case ELFDATA2MSB:
		p.F.Ident.ByteOrder = binary.BigEndian
	default:
		return errors.New("bad ELF byte-order")
	}
	p.F.Ident.Version = Version(ident[EI_VERSION])
	if p.F.Ident.Version != EV_CURRENT {
		return errors.New("bad ELF version")
	}
	p.F.Ident.OSABI = OSABI(ident[EI_OSABI])
	p.F.Ident.ABIVersion = ABIVersion(ident[EI_ABIVERSION])
	// Read actual ELF Header
	// Variables to keep track of the program header.
	// var phoff int64
	// var phentsize int
	// var phnum int
	// // Variables to keep track of the section header.
	// var shoff int64
	// var shentsize int
	// var shnum int
	// var shstrndx int
	return p.ParseELFHeader(p.F.Ident.Class)
}

// CloseFile will close underlying mmap file
func (p *Parser) CloseFile() error {
	return p.fs.Close()
}

// ParseELFHeader reads the raw elf header depending on the ELF Class (32 or 64).
func (p *Parser) ParseELFHeader(c Class) error {

	switch c {
	case ELFCLASS32:
		hdr := NewELF32Header()
		n, err := p.fs.Seek(0, io.SeekStart)
		if err != nil {
			errString := fmt.Errorf(
				"failed to seek start of stream with error : %v , read %d expected %d",
				err, n, EI_NIDENT,
			)
			return errors.New(errString.Error())
		}
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, hdr); err != nil {
			return err
		}
		p.F.Header32 = hdr
		return nil
	case ELFCLASS64:
		hdr := NewELF64Header()
		n, err := p.fs.Seek(0, io.SeekStart)
		if err != nil {
			errString := fmt.Errorf(
				"failed to seek start of stream with error : %v , read %d expected %d",
				err, n, EI_NIDENT,
			)
			return errors.New(errString.Error())
		}
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, hdr); err != nil {
			return err
		}
		p.F.Header64 = hdr
		return nil
	default:
		return errors.New("unknown ELF Class")
	}
}
