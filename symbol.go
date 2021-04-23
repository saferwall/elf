package elf

const Sym64Size = 24

// ELF64SymbolTableEntry represents information needed to locate and relocate
// a program's symbolic definitions, it's an array of SymbolTableEntry
type ELF64SymbolTableEntry struct {
	Name  uint32 // String table index of name.
	Info  uint8  // Type and binding information.
	Other uint8  // Reserved (not used).
	Shndx uint16 // Section index of symbol
	Value uint64 // Symbol value.
	Size  uint64 // Size of associated object.
}

// ELF32SymbolTableEntry represents information needed to locate and relocate
// a program's symbolic definitions, it's an array of SymbolTableEntry.
type ELF32SymbolTableEntry struct {
	Name  uint32
	Value uint32
	Size  uint32
	Info  uint8
	Other uint8
	Shndx uint16
}

const Sym32Size = 16

func ST_BIND(info uint8) SymBind { return SymBind(info >> 4) }
func ST_TYPE(info uint8) SymType { return SymType(info & 0xF) }
func ST_INFO(bind SymBind, typ SymType) uint8 {
	return uint8(bind)<<4 | uint8(typ)&0xf
}
func ST_VISIBILITY(other uint8) SymVis { return SymVis(other & 3) }
