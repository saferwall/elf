package elf

import (
	"compress/zlib"
	"io"
)

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

// ELF64SectionHeader represents the section header of ELF 64-bit binaries.
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

// Standard sections are sections that dominate ELF binaries.
// such as :
// | Name   |      Type      |       Flags      |      Usage       |
// |==-------------------------------------------------------------|
// | .bss   | SHT_NOBITS     |        A,W       | Unitialized data |
// |---------------------------------------------------------------|
// |.data   | SHT_PROGBITS   |        A,W       | Initialized data |
// |---------------------------------------------------------------|
// |.interop| SHT_PROGBITS   | [A] | Program interpreter path name |
// |---------------------------------------------------------------|
// |.rodata | SHT_PROGBITS   | A 				| Read only data ()|
// |---------------------------------------------------------------|
// |.text   | SHT_PROGBITS   |         A, X    |  Executable code  |
// |---------------------------------------------------------------|

// ELF64CompressionHeader defines the compression info of the section.
type ELF64CompressionHeader struct {
	Type      uint32
	_         uint32 // Reserved
	Size      uint64
	AddrAlign uint64
}

// ELF32 Compression header.
type ELF32CompressionHeader struct {
	Type      uint32
	Size      uint32
	AddrAlign uint32
}

// ELFSection32 represents a single ELF section in a 32-bit binary.
type ELFSection32 struct {
	ELF32SectionHeader
	compressionType   CompressionType
	compressionOffset int64
	SectionName       string
	// Size is the size of this section (compressed) in the file in bytes.
	Size uint32
	// sectionReader is used to unpack byte data to decode section name
	sr *io.SectionReader
}

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *ELFSection32) Data() ([]byte, error) {

	var rs io.ReadSeeker
	data := make([]byte, s.Size)

	if s.Flags&uint32(SHF_COMPRESSED) == 0 {
		rs = io.NewSectionReader(s.sr, 0, 1<<63-1)
	} else if s.compressionType == COMPRESS_ZLIB {
		rs = &readSeekerFromReader{
			reset: func() (io.Reader, error) {
				fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.Size)-s.compressionOffset)
				return zlib.NewReader(fr)
			},
			size: int64(s.Size),
		}
	}
	n, err := io.ReadFull(rs, data)
	return data[0:n], err
}

// ELFSection64 represents a single ELF section in a 32-bit binary.
type ELFSection64 struct {
	ELF64SectionHeader
	compressionType   CompressionType
	compressionOffset int64
	SectionName       string
	// Size is the size of this section (compressed) in the file in bytes.
	Size uint64
	// sectionReader is used to unpack byte data to decode section name
	sr *io.SectionReader
}

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *ELFSection64) Data() ([]byte, error) {

	var rs io.ReadSeeker
	data := make([]byte, s.Size)

	if s.Flags&uint64(SHF_COMPRESSED) == 0 {
		rs = io.NewSectionReader(s.sr, 0, 1<<63-1)
	} else if s.compressionType == COMPRESS_ZLIB {
		rs = &readSeekerFromReader{
			reset: func() (io.Reader, error) {
				fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.Size)-s.compressionOffset)
				return zlib.NewReader(fr)
			},
			size: int64(s.Size),
		}
	}
	n, err := io.ReadFull(rs, data)
	return data[0:n], err
}
