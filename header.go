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
