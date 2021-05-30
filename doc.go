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

// Standard sections are sections that dominate ELF binaries.
// ----------------------------------------------------------------
// | Name   |      Type      |       Flags      |      Usage       |
// |==-------------------------------------------------------------|
// | .bss   | SHT_NOBITS     |        A,W       | Unitialized data |
// |---------------------------------------------------------------|
// |.data   | SHT_PROGBITS   |        A,W       | Initialized data |
// |---------------------------------------------------------------|
// |.interop| SHT_PROGBITS   | [A] | Program interpreter path name |
// |---------------------------------------------------------------|
// |.rodata | SHT_PROGBITS   | A 				| Read only data ()|
// |---------------------------------------------------------------|
// |.text   | SHT_PROGBITS   |         A, X    |  Executable code  |
// |---------------------------------------------------------------|
