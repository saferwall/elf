package elf

import (
	"encoding/hex"
	"strings"
)

func (hdr *FileHeader) String() string {
	var sb strings.Builder

	sb.WriteString("ELF Header :\n")
	magic := hex.EncodeToString(hdr.Ident.Magic[:])
	sb.WriteString("Magic: ")
	sb.WriteString(magic + "\n")
	return sb.String()
}
