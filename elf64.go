// Package elf : elf64.go implements the main structures of the 64-bit ELF file format.
// spec : https://uclibc.org/docs/elf-64-gen.pdf
package elf

import "io"

// ELF64Header represents the executable header of the ELF file format for (64-bit architecture).
type ELF64Header struct {
	Ident     [16]byte // File identification.
	Type      uint16   // File type.
	Machine   uint16   // Machine architecture.
	Version   uint32   // ELF format version.
	Entry     uint64   // Entry point.
	Phoff     uint64   // Program header file offset.
	Shoff     uint64   // Section header file offset.
	Flags     uint32   // Architecture-specific flags.
	Ehsize    uint16   // Size of ELF header in bytes.
	Phentsize uint16   // Size of program header entry.
	Phnum     uint16   // Number of program header entries.
	Shentsize uint16   // Size of section header entry.
	Shnum     uint16   // Number of section header entries.
	Shstrndx  uint16   // Section name strings section.
}

// ELF64ProgramHeader represents the program header table which is an array
// entries describing each program segment (in executable or shared object files)
// sections are grouped into segments for in-memory loading.
type ELF64ProgramHeader struct {
	Type   uint32 // Segment type
	Flags  uint32 // Segment attributes
	Off    uint64 // Offset in file
	Vaddr  uint64 // Virtual Address in memory
	Paddr  uint64 // Reserved
	Filesz uint64 // Size of segment in file
	Memsz  uint64 // Size of segment in memory
	Align  uint64 // Segment alignment
}

// ELF64SectionHeader represents the section header of ELF 64-bit binaries.
type ELF64SectionHeader struct {
	Name      uint32 // Section name index in the Section Header String Table.
	Type      uint32 // Section type.
	Flags     uint64 // Section flags.
	Addr      uint64 // Virtual address in memory.
	Off       uint64 // Offset in file.
	Size      uint64 // Section size in bytes.
	Link      uint32 // Index of a related section.
	Info      uint32 // Miscellaneous information depends on section type.
	AddrAlign uint64 // Address alignment boundary.
	EntSize   uint64 // Size of each entry in the section.
}

// ELF64CompressionHeader defines the compression info of the section.
type ELF64CompressionHeader struct {
	Type      uint32
	_         uint32 // Reserved
	Size      uint64
	AddrAlign uint64
}

// ELF64Section represents a single ELF section in a 32-bit binary.
type ELF64Section struct {
	ELF64SectionHeader
	compressionType   CompressionType
	compressionOffset int64
	SectionName       string
	// Size is the size of this section (compressed) in the file in bytes.
	Size uint64
	// sectionReader is used to unpack byte data to decode section name
	sr *io.SectionReader
}

// ELF64DynamicTableEntry represents the Dynamic structure.
// The ".dynamic" section contains an array of them.
type ELF64DynamicTableEntry struct {
	Tag int64  // Identifies the type of the dynamic table entry.
	Val uint64 // Represents integer values
}
