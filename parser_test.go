package elf

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Run Tests against readelf output on /bin/ls.
func TestParser(t *testing.T) {
	t.Run("TestParseIdent", func(t *testing.T) {
		testCases := []struct {
			path          string
			expectedIdent FileIdent
		}{
			{
				path: "/bin/ls",
				expectedIdent: FileIdent{
					Magic:      [4]byte{0x7f, 'E', 'L', 'F'},
					Class:      ELFCLASS64,
					Data:       ELFDATA2LSB,
					Version:    EV_CURRENT,
					OSABI:      ELFOSABI_NONE,
					ABIVersion: ELFABIVersion_CURRENT,
					ByteOrder:  binary.LittleEndian,
				},
			},
		}

		for _, tt := range testCases {
			p, err := New(tt.path)
			if err != nil {
				t.Fatal("failed to create new parser with error :", err)
			}
			err = p.ParseIdent()
			if err != nil {
				t.Fatal("failed to parse ident with error :", err)
			}
			assert.EqualValues(t, tt.expectedIdent, p.F.Ident, "expected ident equal")
		}

	})
	t.Run("TestParseHeader", func(t *testing.T) {
		testCases := []struct {
			path           string
			expectedIdent  FileIdent
			expectedHeader *ELF64Header
		}{
			{
				path: "/bin/ls",
				expectedIdent: FileIdent{
					Magic:      [4]byte{0x7f, 'E', 'L', 'F'},
					Class:      ELFCLASS64,
					Data:       ELFDATA2LSB,
					Version:    EV_CURRENT,
					OSABI:      ELFOSABI_NONE,
					ABIVersion: ELFABIVersion_CURRENT,
					ByteOrder:  binary.LittleEndian,
				},
				expectedHeader: &ELF64Header{
					Ident:     [16]byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					Type:      uint16(ET_DYN),
					Machine:   uint16(EM_X86_64),
					Version:   uint32(EV_CURRENT),
					Entry:     0x67d0,
					Phoff:     64,
					Shoff:     140224,
					Flags:     0x0,
					Ehsize:    64,
					Phentsize: 56,
					Phnum:     13,
					Shentsize: 64,
					Shnum:     30,
					Shstrndx:  29,
				},
			},
		}

		for _, tt := range testCases {
			p, err := New(tt.path)
			if err != nil {
				t.Fatal("failed to create new parser with error :", err)
			}
			err = p.ParseIdent()
			if err != nil {
				t.Fatal("failed to parse ident with error :", err)
			}
			assert.EqualValues(t, tt.expectedIdent, p.F.Ident, "expected ident equal")
			err = p.ParseELFHeader(ELFCLASS64)
			if err != nil {
				t.Fatal("failed to parse ELF header with error :", err)
			}
			assert.EqualValues(t, tt.expectedHeader, p.F.Header64, "expected header equal")
		}
	})
}
