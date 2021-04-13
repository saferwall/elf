package elf

import "encoding/binary"

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

// File is an in-memory iterable representation of a raw elf binary.
// this is merely used to ease the use of the package as a library
// and allow feature modification and rebuilding of ELF files.
type File struct {
	Ident            FileIdent
	Header32         ELF32Header
	Header64         ELF64Header
	SectionHeaders32 []ELF32SectionHeader
	SectionHeaders64 []ELF64SectionHeader
	ProgramHeader64  []ELF64ProgramHeader64
	Sections32       []*ELFSection32
	Sections64       []*ELFSection64
}

// Class returns ELFClass of the binary (designates the target architecture of the binary x64 or x86)
func (f *File) Class() Class {
	return f.Ident.Class
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
