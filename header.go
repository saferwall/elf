package elf

import "debug/elf"

// NewELF32Header creates a new ELF 32-bit header.
func NewELF32Header() ELF32Header {
	return ELF32Header{}
}

// GetIdent returns identifier array EI_IDENT.
func (h ELF32Header) GetIdent() [EI_NIDENT]byte {
	return h.Ident
}

// GetType returns file type.
func (h ELF32Header) GetType() uint16 {
	return h.Type
}

// GetMachine returns ELF target machine.
func (h ELF32Header) GetMachine() uint16 {
	return h.Machine
}

// GetEntry returns entrypoint (virtual address) of ELF binary.
func (h ELF32Header) GetEntry() uint32 {
	return h.Entry
}

// ProgramHeadersOffset returns the file offset to the program headers.
func (h ELF32Header) ProgramHeadersOffset() uint32 {
	return h.Phoff
}

// SectionHeadersOffset returns the file offset to the section headers.
func (h ELF32Header) SectionHeadersOffset() uint32 {
	return h.Shoff
}

// SectionHeadersNum returns the number of section headers is in the section headers table.
func (h ELF32Header) SectionHeadersNum() uint16 {
	return h.Shnum
}

// SectionHeadersEntSize returns the size of a section headers entry
func (h ELF32Header) SectionHeadersEntSize() uint16 {
	return h.Shentsize
}

// Size returns the ELF Header size in bytes.
func (h ELF32Header) Size() uint16 {
	return h.Ehsize
}

// NewELF64Header creates a new ELF 64-bit header.
func NewELF64Header() ELF64Header {
	return ELF64Header{}
}

// GetIdent returns identifier array EI_IDENT.
func (h ELF64Header) GetIdent() [elf.EI_NIDENT]byte {
	return h.Ident
}

// GetType returns file type.
func (h ELF64Header) GetType() uint16 {
	return h.Type
}

// GetMachine returns ELF target machine.
func (h ELF64Header) GetMachine() uint16 {
	return h.Machine
}

// GetEntry returns entrypoint (virtual address) of ELF binary.
func (h ELF64Header) GetEntry() uint64 {
	return h.Entry
}

// ProgramHeadersOffset returns the file offset to the program headers.
func (h ELF64Header) ProgramHeadersOffset() uint64 {
	return h.Phoff
}

// SectionHeadersOffset returns the file offset to the section headers.
func (h ELF64Header) SectionHeadersOffset() uint64 {
	return h.Shoff
}

// SectionHeadersNum returns the number of section headers is in the section headers table.
func (h ELF64Header) SectionHeadersNum() uint16 {
	return h.Shnum
}

// SectionHeadersEntSize returns the size of a section headers entry
func (h ELF64Header) SectionHeadersEntSize() uint16 {
	return h.Shentsize
}

// Size returns the ELF Header size in bytes.
func (h ELF64Header) Size() uint16 {
	return h.Ehsize
}
