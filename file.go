package elf

import "encoding/binary"

// FileIdent is a representation of the raw ident array (first 16 bytes of an ELF file)
type FileIdent struct {
	// Ident array
	Magic      Magic            `json:"magic"`
	Class      Class            `json:"class"`
	Data       Data             `json:"data"`
	OSABI      OSABI            `json:"os_abi"`
	Version    Version          `json:"version"`
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
	FileHeader FileHeader
	Header32   *ELF32Header
	Header64   *ELF64Header
}
