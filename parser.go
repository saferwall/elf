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
	// Read the ELF Header E_Ident array.
	// This step helps find out the architecture
	// that the binary targets, as well as OS ABI version
	// and other compilation artefact.
	n, err := p.fs.ReadAt(ident, 0)
	if n != EI_NIDENT || err != nil {
		return err
	}

	if n != 16 || string(ident[:4]) != ELFMAG {
		return errors.New("bad magic number " + string(ident[:4]) + " expected : " + ELFMAG)
	}

	copy(p.F.Ident.Magic[:], ident[:4])

	if !IsValidELFClass(Class(ident[EI_CLASS])) {
		return errors.New("invalid ELF class")
	}
	if !IsValidByteOrder(Data(ident[EI_DATA])) {
		return errors.New("invalid ELF byte order")
	}
	if !IsValidVersion(Version(ident[EI_VERSION])) {
		return errors.New("bad ELF version")
	}

	p.F.Ident.Class = Class(ident[EI_CLASS])
	p.F.Ident.Data = Data(ident[EI_DATA])
	p.F.Ident.ByteOrder = ByteOrder(Data(ident[EI_DATA]))
	p.F.Ident.Version = Version(ident[EI_VERSION])
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
		return p.parseELFHeader32()
	case ELFCLASS64:
		return p.parseELFHeader64()
	default:
		return errors.New("unknown ELF Class")
	}
}

// parseELFHeader32 parses specifically 32-bit built ELF binaries.
func (p *Parser) parseELFHeader32() error {
	hdr := NewELF32Header()
	n, err := p.fs.Seek(0, io.SeekStart)
	if err != nil {
		errString := fmt.Errorf(
			"failed to seek start of stream with error : %v , read %d expected %d",
			err, n, EI_NIDENT,
		)
		return errors.New(errString.Error())
	}
	if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &hdr); err != nil {
		return err
	}
	p.F.Header32 = hdr
	return nil
}

// parseELFHeader64 parses specifically 64-bit built ELF binaries.
func (p *Parser) parseELFHeader64() error {
	hdr := NewELF64Header()
	n, err := p.fs.Seek(0, io.SeekStart)
	if err != nil {
		errString := fmt.Errorf(
			"failed to seek start of stream with error : %v , read %d expected %d",
			err, n, EI_NIDENT,
		)
		return errors.New(errString.Error())
	}
	if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &hdr); err != nil {
		return err
	}
	p.F.Header64 = hdr
	return nil
}

// ParseELFSectionHeader reads the raw elf section header.
func (p *Parser) ParseELFSectionHeader(c Class) error {

	switch c {
	case ELFCLASS32:
		return p.parseELFSectionHeader32()
	case ELFCLASS64:
		return p.parseELFSectionHeader64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFSectionHeader32 parses specifically the raw elf section header of 32-bit binaries.
func (p *Parser) parseELFSectionHeader32() error {
	if p.F.Header32 == NewELF32Header() {
		return errors.New("header need to be parsed first")
	}
	if p.F.Header32.Shnum == 0 || p.F.Header32.Shoff == 0 {
		return errors.New("ELF file doesn't contain any section header table")
	}
	shnum := p.F.Header32.SectionHeadersNum()
	shoff := p.F.Header32.SectionHeadersOffset()
	shentz := p.F.Header32.Shentsize

	names := make([]uint32, shnum)
	sectionHeaders := make([]ELF32SectionHeader, shnum)
	for i := 0; uint16(i) < shnum; i++ {
		// Section index 0, and indices in the range 0xFF00–0xFFFF are reserved for special purposes.
		offset := int64(shoff) + int64(i)*int64(shentz)
		_, err := p.fs.Seek(offset, io.SeekStart)
		if err != nil {
			return err
		}
		// section header file offset
		var sh ELF32SectionHeader
		if err := binary.Read(p.fs, p.F.Ident.ByteOrder, &sh); err != nil {
			return err
		}
		names[i] = sh.Name
		sectionHeaders[i] = sh
		p.F.SectionHeaders32 = sectionHeaders
		p.sr = io.NewSectionReader(p.fs, int64(sh.Off), int64(sh.Size))
	}
	return nil
}

// parseELFSectionHeader64 parses specifically the raw elf section header of 64-bit binaries.
func (p *Parser) parseELFSectionHeader64() error {
	if p.F.Header64 == NewELF64Header() {
		return errors.New("header need to be parsed first")
	}
	if p.F.Header64.Shnum == 0 || p.F.Header64.Shoff == 0 {
		return errors.New("ELF file doesn't contain any section header table")
	}
	shnum := p.F.Header64.SectionHeadersNum()
	shoff := p.F.Header64.SectionHeadersOffset()
	shentz := p.F.Header64.Shentsize

	names := make([]uint32, shnum)
	sectionHeaders := make([]ELF64SectionHeader, shnum)
	for i := 0; uint16(i) < shnum; i++ {
		// Section index 0, and indices in the range 0xFF00–0xFFFF are reserved for special purposes.
		offset := int64(shoff) + int64(i)*int64(shentz)
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
		sectionHeaders[i] = sh
		p.F.SectionHeaders64 = sectionHeaders
		p.sr = io.NewSectionReader(p.fs, int64(sh.Off), int64(sh.Size))
	}
	return nil
}
