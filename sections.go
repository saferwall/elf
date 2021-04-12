package elf

import (
	"compress/zlib"
	"io"
)

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

// Standard sections are the quintessential sections that dominate ELF binaries.
// such as :
// | Name   |      Type      |       Flags      |      Usage       |
// |==-------------------------------------------------------------|
// | .bss   | SHT_NOBITS     |        A,W       | Unitialized data |
// |---------------------------------------------------------------|
// |.data   | SHT_PROGBITS   |        A,W       | Initialized data |
// |---------------------------------------------------------------|
// |.interop| SHT_PROGBITS   | [A] | Program interpreter path name |
// |---------------------------------------------------------------|
// |.rodata | SHT_PROGBITS   | A | Read only data (constants & literals)|
// |---------------------------------------------------------------|
// |.text   | SHT_PROGBITS   |         A, X    |  Executable code  |
// |---------------------------------------------------------------|
// |---------------------------------------------------------------|
