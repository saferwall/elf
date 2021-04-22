package elf

import (
	"compress/zlib"
	"io"
)

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *ELF32Section) Data() ([]byte, error) {

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

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *ELF64Section) Data() ([]byte, error) {

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
