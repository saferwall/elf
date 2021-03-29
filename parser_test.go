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
				path: "./test/ls",
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
				path: "./test/ls",
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
	t.Run("TestParseSectionHeaders", func(t *testing.T) {
		testCases := []struct {
			path                   string
			expectedIdent          FileIdent
			expectedHeader         *ELF64Header
			expectedSectionHeaders []*ELF64SectionHeader
		}{
			{
				path: "test/ls",
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
				expectedSectionHeaders: []*ELF64SectionHeader{
					{
						Name:      0,
						Type:      0,
						Flags:     0,
						Addr:      0,
						Off:       0,
						Size:      0,
						Link:      0,
						Info:      0,
						AddrAlign: 0,
						EntSize:   0,
					}, {
						Name:      11,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x318,
						Off:       0x318,
						Size:      0x1c,
						Link:      0,
						Info:      0,
						AddrAlign: 1,
						EntSize:   0,
					}, {
						Name:      19,
						Type:      uint32(SHT_NOTE),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x338,
						Off:       0x338,
						Size:      0x20,
						Link:      0,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0,
					}, {
						Name:      38,
						Type:      uint32(SHT_NOTE),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x358,
						Off:       0x358,
						Size:      0x24,
						Link:      0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0,
					}, {
						Name:      57,
						Type:      uint32(SHT_NOTE),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x37c,
						Off:       0x37c,
						Size:      0x20,
						Link:      0x0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0x0,
					}, {
						Name:      71,
						Type:      uint32(SHT_GNU_HASH),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x3a0,
						Off:       0x3a0,
						Size:      0xe4,
						Link:      0x6,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x0,
					}, {
						Name:      81,
						Type:      uint32(SHT_DYNSYM),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x488,
						Off:       0x488,
						Size:      0xd08,
						Link:      7,
						Info:      1,
						AddrAlign: 8,
						EntSize:   0x18,
					}, {
						Name:      89,
						Type:      uint32(SHT_STRTAB),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x1190,
						Off:       0x1190,
						Size:      0x64c,
						Link:      0x0,
						Info:      0,
						AddrAlign: 1,
						EntSize:   0x0,
					}, {
						Name:      97,
						Type:      uint32(SHT_GNU_VERSYM),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x17dc,
						Off:       0x17dc,
						Size:      0x116,
						Link:      0x6,
						Info:      0,
						AddrAlign: 2,
						EntSize:   0x2,
					}, {
						Name:      110,
						Type:      uint32(SHT_GNU_VERNEED),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x18f8,
						Off:       0x18f8,
						Size:      0x70,
						Link:      0x7,
						Info:      1,
						AddrAlign: 8,
						EntSize:   0x0,
					}, {
						Name:      125,
						Type:      uint32(SHT_RELA),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x1968,
						Off:       0x1968,
						Size:      0x1350,
						Link:      0x6,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x18,
					}, {
						Name:      135,
						Type:      uint32(SHT_RELA),
						Flags:     uint64(SHF_ALLOC + SHF_INFO_LINK),
						Addr:      0x2cb8,
						Off:       0x2cb8,
						Size:      0x9f0,
						Link:      0x6,
						Info:      25,
						AddrAlign: 8,
						EntSize:   0x18,
					}, {
						Name:      145,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x4000,
						Off:       0x4000,
						Size:      0x1b,
						Link:      0x0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0x0,
					}, {
						Name:      140,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x4020,
						Off:       0x4020,
						Size:      0x6b0,
						Link:      0,
						Info:      0,
						AddrAlign: 16,
						EntSize:   0x10,
					}, {
						Name:      151,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x46d0,
						Off:       0x46d0,
						Size:      0x30,
						Link:      0,
						Info:      0,
						AddrAlign: 16,
						EntSize:   0x10,
					}, {
						Name:      160,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x4700,
						Off:       0x4700,
						Size:      0x6a0,
						Link:      0x0,
						Info:      0,
						AddrAlign: 16,
						EntSize:   0x10,
					}, {
						Name:      169,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x4da0,
						Off:       0x4da0,
						Size:      0x127d2,
						Link:      0x0,
						Info:      0,
						AddrAlign: 16,
						EntSize:   0x0,
					}, {
						Name:      175,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC + SHF_EXECINSTR),
						Addr:      0x17574,
						Off:       0x17574,
						Size:      0xd,
						Link:      0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0x0,
					}, {
						Name:      181,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x18000,
						Off:       0x18000,
						Size:      0x5249,
						Link:      0,
						Info:      0,
						AddrAlign: 32,
						EntSize:   0x0,
					}, {
						Name:      189,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x1d24c,
						Off:       0x1d24c,
						Size:      0x92c,
						Link:      0x0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0x0,
					}, {
						Name:      203,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_ALLOC),
						Addr:      0x1db78,
						Off:       0x1db78,
						Size:      0x2fd8,
						Link:      0x0,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x0,
					}, {
						Name:      213,
						Type:      uint32(SHT_INIT_ARRAY),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x22010,
						Off:       0x21010,
						Size:      0x8,
						Link:      0x0,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x8,
					}, {
						Name:      225,
						Type:      uint32(SHT_FINI_ARRAY),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x22018,
						Off:       0x21018,
						Size:      0x8,
						Link:      0x0,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x8,
					}, {
						Name:      237,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x22020,
						Off:       0x21020,
						Size:      0xa38,
						Link:      0x0,
						Info:      0,
						AddrAlign: 32,
						EntSize:   0x0,
					}, {
						Name:      250,
						Type:      uint32(SHT_DYNAMIC),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x22a58,
						Off:       0x21a58,
						Size:      0x200,
						Link:      0x7,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x10,
					}, {
						Name:      155,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x22c58,
						Off:       0x21c58,
						Size:      0x3a0,
						Link:      0,
						Info:      0,
						AddrAlign: 8,
						EntSize:   0x8,
					}, {
						Name:      259,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x23000,
						Off:       0x22000,
						Size:      0x268,
						Link:      0,
						Info:      0,
						AddrAlign: 32,
						EntSize:   0x0,
					}, {
						Name:      265,
						Type:      uint32(SHT_NOBITS),
						Flags:     uint64(SHF_WRITE + SHF_ALLOC),
						Addr:      0x23280,
						Off:       0x22268,
						Size:      0x12d8,
						Link:      0,
						Info:      0,
						AddrAlign: 32,
						EntSize:   0x0,
					}, {
						Name:      270,
						Type:      uint32(SHT_PROGBITS),
						Flags:     uint64(SHF_NONE),
						Addr:      0x0,
						Off:       0x22268,
						Size:      0x34,
						Link:      0,
						Info:      0,
						AddrAlign: 4,
						EntSize:   0x0,
					}, {
						Name:      1,
						Type:      uint32(SHT_STRTAB),
						Flags:     uint64(SHF_NONE),
						Addr:      0x0,
						Off:       0x2229c,
						Size:      0x11d,
						Link:      0,
						Info:      0,
						AddrAlign: 1,
						EntSize:   0x0,
					},
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
			err = p.ParseELFSectionHeader(ELFCLASS64)
			if err != nil {
				t.Fatal("failed to parse ELF section headers with error :", err)
			}
			assert.EqualValues(t, tt.expectedSectionHeaders, p.F.SectionHeaders, "expected section headers equal")
		}
	})
}
