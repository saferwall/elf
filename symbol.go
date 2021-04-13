package elf

// SymbolTable represents information needed to locate and relocate
// a program's symbolic definitions, it's an array of SymbolTableEntry
type ELFSymbolTableEntry64 struct {
	Name  uint32 // String table index of name.
	Info  uint8  // Type and binding information.
	Other uint8  // Reserved (not used).
	Shndx uint16 // Section index of symbol
	Value uint64 // Symbol value.
	Size  uint64 // Size of associated object.
}
