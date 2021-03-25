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

// ParseHeader will parse the ELF file header.
func (p *Parser) ParseHeader() error {

	ident := make([]byte, EI_NIDENT)
	var magic [4]byte
	// Read the ELF Header E_Ident array.
	// This step helps find out the architecture
	// that the binary targets, as well as OS ABI version
	// and other compilation artefact.
	n, err := p.fs.ReadAt(ident, 0)
	if n != EI_NIDENT || err != nil {
		return err
	}
	n = copy(magic[:], ident[:4])
	if n != 4 || string(magic[:]) != ELFMAG {
		return errors.New("bad magic number " + string(magic[:]))
	}
	p.F.FileHeader.Ident.Magic = Magic(magic)
	p.F.FileHeader.Ident.Class = Class(ident[EI_CLASS])
	switch p.F.FileHeader.Ident.Class {
	case ELFCLASS32:
	case ELFCLASS64:
	default:
		return errors.New("bad ELF class")
	}
	p.F.FileHeader.Ident.Data = Data(ident[EI_DATA])
	switch p.F.FileHeader.Ident.Data {
	case ELFDATA2LSB:
		p.F.FileHeader.Ident.ByteOrder = binary.LittleEndian
	case ELFDATA2MSB:
		p.F.FileHeader.Ident.ByteOrder = binary.BigEndian
	default:
		return errors.New("bad ELF byte-order")
	}
	p.F.FileHeader.Version = Version(ident[EI_VERSION])
	if p.F.FileHeader.Version != EV_CURRENT {
		return errors.New("bad ELF version")
	}
	p.F.FileHeader.Ident.OSABI = OSABI(ident[EI_OSABI])
	p.F.FileHeader.Ident.ABIVersion = ABIVersion(ident[EI_ABIVERSION])

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
	return p.parseRAWHeader(p.F.FileHeader.Ident.Class)
}

// CloseFile will close underlying mmap file
func (p *Parser) CloseFile() error {
	return p.fs.Close()
}

// parseRAWELFHeader reads the raw elf header depending on the ELF Class (32 or 64).
func (p *Parser) parseRAWHeader(c Class) error {

	switch c {
	case ELFCLASS32:
		hdr := new(ELF32Header)
		n, err := p.fs.Seek(0, io.SeekStart)
		if err != nil {
			errString := fmt.Errorf(
				"failed to seek start of stream with error : %v , read %d expected %d",
				err, n, EI_NIDENT,
			)
			return errors.New(errString.Error())
		}
		if err := binary.Read(p.fs, p.F.FileHeader.Ident.ByteOrder, hdr); err != nil {
			return err
		}
		fmt.Println(hdr)
		p.F.Header32 = hdr
		return nil
	case ELFCLASS64:
		hdr := new(ELF64Header)
		n, err := p.fs.Seek(0, io.SeekStart)
		if err != nil {
			errString := fmt.Errorf(
				"failed to seek start of stream with error : %v , read %d expected %d",
				err, n, EI_NIDENT,
			)
			return errors.New(errString.Error())
		}
		if err := binary.Read(p.fs, p.F.FileHeader.Ident.ByteOrder, hdr); err != nil {
			return err
		}
		fmt.Println(hdr)
		p.F.Header64 = hdr
		return nil
	default:
		return errors.New("unknown ELF Class")
	}
}
