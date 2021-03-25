package elf

import (
	"fmt"
	"strings"
)

// PrettyString is used for printing cli output.
func (hdr *FileHeader) PrettyString() string {
	var sb strings.Builder

	sb.WriteString("ELF Header :\n")
	sb.WriteString("Magic: ")
	for _, v := range hdr.Ident.Magic[:] {
		s := fmt.Sprintf("%x ", v)
		sb.WriteString(s)
	}
	return sb.String()
}
