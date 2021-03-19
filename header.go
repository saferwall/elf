package elf

// ELF64Header represents the executable header of the ELF file format for (64-bit architecture).
// The first 4 bytes of the eIdent array contain the magic bytes of the ELF file format.
// Indexes 4 through 15 contain other metadata.
// Namely indexes 9 through 15 represent EI_PAD field which designate padding.
// Indexes 4 through 9 are symbolically referred to as : EI_CLASS, EI_DATA,EI_VERSION, EI_OSABI and
// EI_ABIVERSION.
// EI_CLASS byte represents the binary class (specifies whether a 32-Bit or 64-Bit binary).
// EI_DATA byte specifies whether integers are encoded as Big-Endian or Little-Endian
// EI_VERSION byte specifies the current elf version, currently the only valid value is EV_CURRENT=1.
type ELF64Header struct {
	eIdent     [16]byte // Magic number and other info
	eType      uint16   // Object file type
	eMachine   uint16   // Architecture
	eVersion   uint32   // Object file version
	eEntry     uint64   // Entrypoint virtual address
	ePHOff     uint64   // Program header table offset
	eSHOff     uint64   // Section heaeder table offset
	eFlags     uint32   // Processor-specific flags
	eEHSize    uint16   // ELF header size in bytes
	ePHEntSize uint16   // Program header table entry size
	ePHEntNum  uint16   // Program header table entry count
	eSHEntSize uint16   // Section header table entry size
	eSHEntNum  uint16   // Section header table entry count
	eSHStrndx  uint16   // Section header string table index
}
