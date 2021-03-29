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
	sr *io.SectionReader
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
	return nil
}

// CloseFile will close underlying mmap file
func (p *Parser) CloseFile() error {
	return p.fs.Close()
}

// ParseELFHeader reads the raw elf header depending on the ELF Class (32 or 64).
func (p *Parser) ParseELFHeader(c Class) error {

	// Because of parsing ambiguitiy we need parentheses here
	// ref : https://golang.org/ref/spec#Composite_literals
	// The two structs are comparable because all the fields are
	// comparable values https://golang.org/ref/spec#Comparison_operators
	if (FileIdent{} == p.F.Ident) {
		err := p.ParseIdent()
		if err != nil {
			return err
		}
	}
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

// ParseELFSectionHeader reads the raw elf section header.
func (p *Parser) ParseELFSectionHeader(c Class) error {
	if p.F.Header64 == nil {
		return errors.New("header need to be parsed first")
	}
	if p.F.Header64.Shnum == 0 || p.F.Header64.Shoff == 0 {
		return errors.New("ELF file doesn't contain any section header table")
	}
	names := make([]uint32, p.F.Header64.Shnum)
	sectionHeaders := make([]*ELF64SectionHeader, p.F.Header64.Shnum)
	for i := 0; uint16(i) < p.F.Header64.Shnum; i++ {
		// Section index 0, and indices in the range 0xFF00–0xFFFF are reserved for special purposes.
		offset := int64(p.F.Header64.Shoff) + int64(i)*int64(p.F.Header64.Shentsize)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}
		// section header file offset
		var sh ELF64SectionHeader
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			return err
		}
		names[i] = sh.Name
		sectionHeaders[i] = &sh
		p.F.SectionHeaders = sectionHeaders
		p.sr = io.NewSectionReader(p.fs, int64(sh.Off), int64(sh.Size))
	}
	return nil
}
