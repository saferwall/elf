// Package elf : elf32.go implements the main structures of the 32-bit ELF file format.
// spec : https://refspecs.linuxbase.org/elf/elf.pdf
package elf

import "io"

// ELF32Header represents the executable header of the ELF file format for (32-bit architecture).
type ELF32Header struct {
	Ident     [16]byte // File identification.
	Type      uint16   // File type.
	Machine   uint16   // Machine architecture.
	Version   uint32   // ELF format version.
	Entry     uint32   // Entry point.
	Phoff     uint32   // Program header file offset.
	Shoff     uint32   // Section header file offset.
	Flags     uint32   // Architecture-specific flags.
	Ehsize    uint16   // Size of ELF header in bytes.
	Phentsize uint16   // Size of program header entry.
	Phnum     uint16   // Number of program header entries.
	Shentsize uint16   // Size of section header entry.
	Shnum     uint16   // Number of section header entries.
	Shstrndx  uint16   // Section name strings section.
}

// ELF32ProgramHeader represents the program header table which is an array
// entries describing each program segment (in executable or shared object files)
// sections are grouped into segments for in-memory loading.
type ELF32ProgramHeader struct {
	Type   uint32 // Segment type
	Off    uint32 // Offset in file
	Vaddr  uint32 // Virtual Address in memory
	Paddr  uint32 // Reserved
	Filesz uint32 // Size of segment in file
	Memsz  uint32 // Size of segment in memory
	Flags  uint32 // Segment attributes
	Align  uint32 // Segment alignment
}

// ELF32SectionHeader represents the section header of ELF 64-bit binaries.
type ELF32SectionHeader struct {
	Name      uint32 // Section name index in the Section Header String Table.
	Type      uint32 // Section type.
	Flags     uint32 // Section flags.
	Addr      uint32 // Virtual address in memory.
	Off       uint32 // Offset in file.
	Size      uint32 // Section size in bytes.
	Link      uint32 // Index of a related section.
	Info      uint32 // Miscellaneous information depends on section type.
	AddrAlign uint32 // Address alignment boundary.
	EntSize   uint32 // Size of each entry in the section.
}

// ELF32 Compression header.
type ELF32CompressionHeader struct {
	Type      uint32
	Size      uint32
	AddrAlign uint32
}

// ELF32Section represents a single ELF section in a 32-bit binary.
type ELF32Section struct {
	ELF32SectionHeader
	compressionType   CompressionType
	compressionOffset int64
	SectionName       string
	// Size is the size of this section (compressed) in the file in bytes.
	Size uint32
	// sectionReader is used to unpack byte data to decode section name
	sr *io.SectionReader
}

// ELF32DynamicTableEntry represents the Dynamic structure.
// The ".dynamic" section contains an array of them.
type ELF32DynamicTableEntry struct {
	Tag int32  // Identifies the type of the dynamic table entry.
	Val uint32 // Represents integer values
}
