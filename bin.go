package elf

// ELFBin64 represents a 64-bit ELF binary.
type ELFBin64 struct {
	Header64         ELF64Header
	SectionHeaders64 []ELF64SectionHeader
	ProgramHeaders64 []ELF64ProgramHeader
	Sections64       []*ELF64Section
	Symbols64        []ELF64SymbolTableEntry
}

// ELFBin32 represents a 32-bit ELF binary.
type ELFBin32 struct {
	Header32         ELF32Header
	SectionHeaders32 []ELF32SectionHeader
	ProgramHeaders32 []ELF32ProgramHeader
	Sections32       []*ELF32Section
	Symbols32        []ELF32SymbolTableEntry
}
