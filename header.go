package elf

// ELF Header Structure
// +--------------------+
// + EIDENT	(16 bytes)  + => ELF Compilation metadata.
// +--------------------+
// +   Type (2 bytes)   + => Binary type (relocatable object file or executable binary)
// +--------------------+
// + Machine (2 bytes)  + => Machine architecture.
// +--------------------+
// + Version (4 bytes)  + => ELF File Format version.
// +--------------------+
// + PHOffset (4 bytes) + => File Offset to the beginning of the program header.
// +--------------------+
// + SHOffset (4 bytes)	+ => File Offset to the beginning of the section header.
// +--------------------+
// + Entry (4 bytes)	+ => Binary entrypoint (Virtual Address where execution starts).
// +--------------------+
// + Flags (4 bytes)	+ => Flags specific to the compilation architecture.
// +--------------------+
// +   EHSize (2 bytes) + => Size in bytes of the executable header.
// +--------------------+
// + PHEntSize (2 bytes)+ => Program headers size.
// +--------------------+
// +   PHNum (2 bytes)  + => Program headers number.
// +--------------------+
// + SHEntSize (2 bytes)+ => Section headers size.
// +--------------------+
// +   SHNum (2 bytes)  + => Section headers numbers.
// +--------------------+
// + SHStrndx (2 bytes) + => Index of the string table ".shstrtab"
// +--------------------+

// Ident the first 4 bytes of the eIdent array contain the magic bytes of the ELF file format.
// Indexes 4 through 15 contain other metadata.
// Namely indexes 9 through 15 represent EI_PAD field which designate padding.
// Indexes 4 through 9 are symbolically referred to as : EI_CLASS, EI_DATA,EI_VERSION, EI_OSABI and
// EI_ABIVERSION.
// EI_CLASS byte represents the binary class (specifies whether a 32-Bit or 64-Bit binary).
// EI_DATA byte specifies whether integers are encoded as Big-Endian or Little-Endian
// EI_VERSION byte specifies the current elf version, currently the only valid value is EV_CURRENT=1.

// ELF64Header represents the executable header of the ELF file format for (64-bit architecture).
type ELF64Header struct {
	Ident     [16]byte // File identification.
	Type      uint16   // File type.
	Machine   uint16   // Machine architecture.
	Version   uint32   // ELF format version.
	Entry     uint64   // Entry point.
	Phoff     uint64   // Program header file offset.
	Shoff     uint64   // Section header file offset.
	Flags     uint32   // Architecture-specific flags.
	Ehsize    uint16   // Size of ELF header in bytes.
	Phentsize uint16   // Size of program header entry.
	Phnum     uint16   // Number of program header entries.
	Shentsize uint16   // Size of section header entry.
	Shnum     uint16   // Number of section header entries.
	Shstrndx  uint16   // Section name strings section.
}

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

// ELF32Header represents the executable header of the ELF file format for (32-bit architecture).
type ELF32Header struct {
	Ident     [16]byte // File identification.
	Type      uint16   // File type.
	Machine   uint16   // Machine architecture.
	Version   uint32   // ELF format version.
	Entry     uint32   // Entry point.
	Phoff     uint32   // Program header file offset.
	Shoff     uint32   // Section header file offset.
	Flags     uint32   // Architecture-specific flags.
	Ehsize    uint16   // Size of ELF header in bytes.
	Phentsize uint16   // Size of program header entry.
	Phnum     uint16   // Number of program header entries.
	Shentsize uint16   // Size of section header entry.
	Shnum     uint16   // Number of section header entries.
	Shstrndx  uint16   // Section name strings section.
}

// NewELF32Header creates a new ELF 32-bit header.
func NewELF32Header() ELF32Header {
	return ELF32Header{}
}

// NewELF64Header creates a new ELF 64-bit header.
func NewELF64Header() ELF64Header {
	return ELF64Header{}
}

// GetIdent returns identifier array EI_IDENT.
func (h ELF64Header) GetIdent() [EI_NIDENT]byte {
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
func (h ELF64Header) Size() uint64 {
	return uint64(h.Ehsize)
}
