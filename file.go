package elf

import (
	"encoding/binary"
	"errors"
)

// FileIdent is a representation of the raw ident array (first 16 bytes of an ELF file)
type FileIdent struct {
	// Ident array
	Magic      Magic            `json:"magic"`
	Class      Class            `json:"class"`
	Data       Data             `json:"data"`
	Version    Version          `json:"version"`
	OSABI      OSABI            `json:"os_abi"`
	ABIVersion ABIVersion       `json:"abi_version"`
	ByteOrder  binary.ByteOrder `json:"byte_order"`
}

// FileHeader is an in-memory representation of the raw elf header.
type FileHeader struct {
	Ident FileIdent
	// ELF Header fields
	Type                   Type    `json:"type"` // object file type
	Machine                Machine `json:"machine"`
	Version                Version `json:"version"`
	Entry                  uint64  `json:"entrypoint"`
	ProgramHeaderOffset    uint64  `json:"program_headers_offset"`
	SectionHeaderOffset    uint64  `json:"section_headers_offset"`
	Flags                  uint32  `json:"processor_flag"`
	Size                   uint16  `json:"header_size"`
	ProgramHeaderEntrySize uint16  `json:"ph_entry_size"`
	ProgramHeaderNum       uint16  `json:"ph_entry_num"`
	SectionHeaderEntrySize uint16  `json:"sh_entry_size"`
	SectionHeaderNum       uint16  `json:"sh_entry_num"`
	SectionHeaderStringIdx uint16  `json:"sh_str_idx"`
}

// SectionTable is required for relocatable files, and optional for loadable files.
type SectionTable struct {
}

// ProgramHeaderTable equired for loadable files, and optional for relocatable files.
// This table describes the loadable segments and other data structures required for loading a program
// or dynamically-linked library in preparation for execution.
type ProgramHeaderTable struct{}

// A Symbol represents an entry in an ELF symbol table section.
type Symbol struct {
	Name        string
	Info, Other byte
	Section     SectionIndex
	Value, Size uint64
	// Version and Library are present only for the dynamic symbol
	// table.
	Version string
	Library string
}

// File is an in-memory iterable representation of a raw elf binary.
// this is merely used to ease the use of the package as a library
// and allow feature modification and rebuilding of ELF files.
type File struct {
	Ident            FileIdent
	Header32         ELF32Header
	Header64         ELF64Header
	SectionHeaders32 []ELF32SectionHeader
	SectionHeaders64 []ELF64SectionHeader
	ProgramHeaders32 []ELF32ProgramHeader
	ProgramHeaders64 []ELF64ProgramHeader
	Sections32       []*ELF32Section
	Sections64       []*ELF64Section
	Symbols32        []ELF32SymbolTableEntry
	Symbols64        []ELF64SymbolTableEntry
	NamedSymbols     []Symbol
}

func NewBinaryFile() *File {
	return &File{
		Ident:            FileIdent{},
		Header32:         ELF32Header{},
		Header64:         ELF64Header{},
		SectionHeaders32: []ELF32SectionHeader{},
		SectionHeaders64: []ELF64SectionHeader{},
		ProgramHeaders32: []ELF32ProgramHeader{},
		ProgramHeaders64: []ELF64ProgramHeader{},
		Sections32:       []*ELF32Section{},
		Sections64:       []*ELF64Section{},
		Symbols32:        []ELF32SymbolTableEntry{},
		Symbols64:        []ELF64SymbolTableEntry{},
		NamedSymbols:     []Symbol{},
	}
}

// Class returns ELFClass of the binary (designates the target architecture of the binary x64 or x86)
func (f *File) Class() Class {
	return f.Ident.Class
}

// ByteOrder returns byte order of the binary.
func (f *File) ByteOrder() binary.ByteOrder {
	return f.Ident.ByteOrder
}

// IsELF64 returns true if the binary was compiled with an x64 architecture target.
func (f *File) IsELF64() bool {
	return f.Ident.Class == ELFCLASS64
}

// SectionNames returns the list of section names
func (f *File) SectionNames() []string {
	if len(f.Sections64) != 0 {
		sectionNames := make([]string, len(f.Sections64))
		for i, s := range f.Sections64 {
			sectionNames[i] = s.SectionName
		}
		return sectionNames
	} else if len(f.Sections32) != 0 {
		sectionNames := make([]string, len(f.Sections64))
		for i, s := range f.Sections32 {
			sectionNames[i] = s.SectionName
		}
		return sectionNames
	}

	return []string{""}
}

// GetSectionByType returns the first section with the given type T (nil otherwise).
func (f *File) GetSectionByType(t SectionType) *ELF64Section {
	for _, s := range f.Sections64 {
		if s.Type == uint32(t) {
			return s
		}
	}
	return nil
}

// stringTable reads and returns the string table given by the
// specified link value.
func (f *File) stringTable(link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections64)) {
		return nil, errors.New("section has invalid string table link")
	}
	return f.Sections64[link].Data()
}

// IsValidELFClass validates the ELF class of the binary.
func IsValidELFClass(c Class) bool {
	switch c {
	case ELFCLASS32:
		return true
	case ELFCLASS64:
		return true
	default:
		return false
	}
}

// IsValidByteOrder validates the ELF byte order field.
func IsValidByteOrder(b Data) bool {
	switch b {
	case ELFDATA2LSB:
		return true
	case ELFDATA2MSB:
		return true
	default:
		return false
	}
}

// IsValidVersion validates against the current default version flag EV_CURRENT.
func IsValidVersion(b Version) bool {
	return b == EV_CURRENT
}

// goByteOrder encodes a Data field to a native Go byte order field.
func ByteOrder(b Data) binary.ByteOrder {
	switch b {
	case ELFDATA2LSB:
		return binary.LittleEndian
	case ELFDATA2MSB:
		return binary.BigEndian
	default:
		return binary.LittleEndian
	}
}
