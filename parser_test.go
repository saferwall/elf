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
}
