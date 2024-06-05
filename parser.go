package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/saferwall/binstream"
)

// Parser implements a parsing engine for the ELF file format.
type Parser struct {
	fs binstream.Stream
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

// NewBytes creates a new instance of parser from a byte slice representig the ELF binary.
func NewBytes(data []byte) (*Parser, error) {
	fs, err := binstream.NewByteStream(data)
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
func (p *Parser) Parse() error {
	err := p.ParseIdent()
	if err != nil {
		return err
	}
	elfClass := p.F.Ident.Class
	err = p.ParseELFHeader(elfClass)
	if err != nil {
		return err
	}
	err = p.ParseELFSectionHeaders(elfClass)
	if err != nil {
		return err
	}
	err = p.ParseELFSections(elfClass)
	if err != nil {
		return err
	}
	err = p.ParseELFProgramHeaders(elfClass)
	if err != nil {
		return err
	}
	err = p.ParseELFSymbols(elfClass, SHT_DYNSYM)
	if err != nil {
		return err
	}
	return nil
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

// ParseELFSectionHeaders reads the raw elf section header.
func (p *Parser) ParseELFSectionHeaders(c Class) error {

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
	}
	return nil
}

// ParseELFSections reads the raw elf sections.
func (p *Parser) ParseELFSections(c Class) error {

	switch c {
	case ELFCLASS32:
		return p.parseELFSections32()
	case ELFCLASS64:
		return p.parseELFSections64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFSections64 parses all sections in a 64-bit ELF binary.
func (p *Parser) parseELFSections64() error {
	if len(p.F.SectionHeaders64) == 0 {
		err := p.parseELFSectionHeader64()
		if err != nil {
			return err
		}
	}
	shnum := p.F.Header64.Shnum
	sections := make([]*ELF64Section, shnum)

	for i := 0; i < int(shnum); i++ {
		s := &ELF64Section{}
		size := p.F.SectionHeaders64[i].Size
		s.ELF64SectionHeader = p.F.SectionHeaders64[i]
		s.sr = io.NewSectionReader(p.fs, int64(s.Off), int64(size))

		if s.Flags&uint64(SHF_COMPRESSED) == 0 {
			s.Size = p.F.SectionHeaders64[i].Size
		} else {
			ch := new(ELF64CompressionHeader)
			err := binary.Read(s.sr, p.F.Ident.ByteOrder, ch)
			if err != nil {
				return errors.New("error reading compressed header " + err.Error())
			}
			s.compressionType = CompressionType(ch.Type)
			s.Size = ch.Size
			s.AddrAlign = ch.AddrAlign
			s.compressionOffset = int64(binary.Size(ch))
		}
		sections[i] = s
	}
	if len(sections) == 0 {
		return errors.New("binary has no sections")
	}
	shstrtab, err := sections[p.F.Header64.Shstrndx].Data()
	if err != nil {
		return errors.New("error reading the section header strings table " + err.Error())
	}

	for i, s := range sections {
		var ok bool
		s.SectionName, ok = getString(shstrtab, int(p.F.SectionHeaders64[i].Name))
		if !ok {
			return errors.New("failed to parse string table")
		}
	}
	p.F.Sections64 = sections
	return nil
}

// parseELFSections32 parses all sections in a 32-bit ELF binary.
func (p *Parser) parseELFSections32() error {
	if len(p.F.SectionHeaders32) == 0 {
		err := p.parseELFSectionHeader32()
		if err != nil {
			return err
		}
	}
	shnum := p.F.Header32.Shnum
	sections := make([]*ELF32Section, shnum)

	for i := 0; i < int(shnum); i++ {
		s := &ELF32Section{}
		size := p.F.SectionHeaders32[i].Size
		s.ELF32SectionHeader = p.F.SectionHeaders32[i]
		s.sr = io.NewSectionReader(p.fs, int64(s.Off), int64(size))

		if s.Flags&uint32(SHF_COMPRESSED) == 0 {
			s.Size = p.F.SectionHeaders32[i].Size
		} else {
			ch := new(ELF32CompressionHeader)
			err := binary.Read(s.sr, p.F.Ident.ByteOrder, ch)
			if err != nil {
				return errors.New("error reading compressed header " + err.Error())
			}
			s.compressionType = CompressionType(ch.Type)
			s.Size = ch.Size
			s.AddrAlign = ch.AddrAlign
			s.compressionOffset = int64(binary.Size(ch))
		}
		sections[i] = s
	}
	if len(sections) == 0 {
		return errors.New("binary has no sections")
	}
	shstrtab, err := sections[p.F.Header32.Shstrndx].Data()
	if err != nil {
		return errors.New("error reading the section header strings table " + err.Error())
	}

	for i, s := range sections {
		var ok bool
		s.SectionName, ok = getString(shstrtab, int(p.F.SectionHeaders32[i].Name))
		if !ok {
			return errors.New("failed to parse string table")
		}
	}
	p.F.Sections32 = sections
	return nil
}

// ParseELFProgramHeaders reads the raw elf program header.
func (p *Parser) ParseELFProgramHeaders(c Class) error {

	switch c {
	case ELFCLASS32:
		return p.parseELFProgramHeaders32()
	case ELFCLASS64:
		return p.parseELFProgramHeaders64()
	default:
		return errors.New("unknown ELF class")
	}
}

// parseELFProgramHeaders64 parses all program header table entries in a 64-bit ELF binary.
func (p *Parser) parseELFProgramHeaders64() error {
	phOff := p.F.Header64.Phoff
	phNum := p.F.Header64.Phnum
	phEntSize := p.F.Header64.Phentsize
	programHeaders := make([]ELF64ProgramHeader, phNum)

	for i := 0; i < int(phNum); i++ {
		off := int64(phOff) + int64(i)*int64(phEntSize)
		p.fs.Seek(off, io.SeekStart)
		var ph ELF64ProgramHeader
		err := binary.Read(p.fs, p.F.Ident.ByteOrder, &ph)
		if err != nil {
			return err
		}
		programHeaders[i] = ph
	}
	p.F.ProgramHeaders64 = programHeaders
	return nil
}

// parseELFProgramHeaders32 parses all program header table entries in a 32-bit ELF binary.
func (p *Parser) parseELFProgramHeaders32() error {
	phOff := p.F.Header32.Phoff
	phNum := p.F.Header32.Phnum
	phEntSize := p.F.Header32.Phentsize
	programHeaders := make([]ELF32ProgramHeader, phNum)

	for i := 0; i < int(phNum); i++ {
		off := int64(phOff) + int64(i)*int64(phEntSize)
		p.fs.Seek(off, io.SeekStart)
		var ph ELF32ProgramHeader
		err := binary.Read(p.fs, p.F.Ident.ByteOrder, &ph)
		if err != nil {
			return err
		}
		programHeaders[i] = ph
	}
	p.F.ProgramHeaders32 = programHeaders
	return nil
}

// ParseELFSymbols returns a slice of Symbols from parsing the symbol table
// with the given type, along with the associated string table
// (the null symbol at index 0 is omitted).
func (p *Parser) ParseELFSymbols(c Class, typ SectionType) error {
	switch c {
	case ELFCLASS64:
		_, _, err := p.getSymbols64(typ)
		return err
	case ELFCLASS32:
		_, _, err := p.getSymbols32(typ)
		return err
	}
	return errors.New("unknown ELF class")
}

func (p *Parser) getSymbols32(typ SectionType) ([]Symbol, []byte, error) {
	symtabSection := p.F.GetSectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}
	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%Sym32Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of SymSize")
	}
	strdata, err := p.F.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros.
	var skip [Sym32Size]byte
	symtab.Read(skip[:])
	symbols := make([]ELF32SymbolTableEntry, symtab.Len()/Sym32Size)
	namedSymbols := make([]Symbol, symtab.Len()/Sym32Size)
	i := 0
	var sym ELF32SymbolTableEntry
	for symtab.Len() > 0 {
		binary.Read(symtab, p.F.ByteOrder(), &sym)
		symbols[i] = sym
		str, _ := getString(strdata, int(sym.Name))
		namedSymbols[i] = Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Index:   SectionIndex(sym.Shndx),
			Value:   uint64(sym.Value),
			Size:    uint64(sym.Size),
			Version: "",
			Library: "",
		}
		i++
	}
	p.F.Symbols32 = symbols
	p.F.NamedSymbols = namedSymbols
	return namedSymbols, strdata, nil
}
func (p *Parser) getSymbols64(typ SectionType) ([]Symbol, []byte, error) {
	symtabSection := p.F.GetSectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}
	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, errors.New("cannot load symbol section")
	}
	symtab := bytes.NewReader(data)
	if symtab.Len()%Sym64Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}
	strdata, err := p.F.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, errors.New("cannot load string table section")
	}
	// The first entry is all zeros.
	var skip [Sym64Size]byte
	symtab.Read(skip[:])
	symbols := make([]ELF64SymbolTableEntry, symtab.Len()/Sym64Size)
	namedSymbols := make([]Symbol, symtab.Len()/Sym64Size)
	i := 0
	var sym ELF64SymbolTableEntry
	for symtab.Len() > 0 {
		binary.Read(symtab, p.F.ByteOrder(), &sym)
		str, _ := getString(strdata, int(sym.Name))
		symbols[i] = ELF64SymbolTableEntry{
			Name:  sym.Name,
			Info:  sym.Info,
			Other: sym.Other,
			Shndx: sym.Shndx,
			Value: sym.Value,
			Size:  sym.Size,
		}
		namedSymbols[i] = Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Index:   SectionIndex(sym.Shndx),
			Value:   sym.Value,
			Size:    sym.Size,
			Version: "",
			Library: "",
		}
		i++
	}
	err = p.ParseGNUVersionTable(strdata)
	if err == nil {
		for i := range namedSymbols {
			namedSymbols[i].Library, namedSymbols[i].Version = p.gnuVersion(i)
		}
	}
	p.F.Symbols64 = symbols
	p.F.NamedSymbols = namedSymbols
	return namedSymbols, strdata, nil
}
