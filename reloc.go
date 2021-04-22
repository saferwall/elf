package elf

// Relocation entries.

// ELF32 Relocations that don't need an addend field.
type Rel32 struct {
	Off  uint32 // Location to be relocated.
	Info uint32 // Relocation type and symbol index.
}

// ELF32 Relocations that need an addend field.
type Rela32 struct {
	Off    uint32 // Location to be relocated.
	Info   uint32 // Relocation type and symbol index.
	Addend int32  // Addend.
}

func R_SYM32(info uint32) uint32      { return info >> 8 }
func R_TYPE32(info uint32) uint32     { return info & 0xff }
func R_INFO32(sym, typ uint32) uint32 { return sym<<8 | typ }

// ELF64 relocations that don't need an addend field.
type Rel64 struct {
	Off  uint64 // Location to be relocated.
	Info uint64 // Relocation type and symbol index.
}

// ELF64 relocations that need an addend field.
type Rela64 struct {
	Off    uint64 // Location to be relocated.
	Info   uint64 // Relocation type and symbol index.
	Addend int64  // Addend.
}

func R_SYM64(info uint64) uint32    { return uint32(info >> 32) }
func R_TYPE64(info uint64) uint32   { return uint32(info) }
func R_INFO(sym, typ uint32) uint64 { return uint64(sym)<<32 | uint64(typ) }
