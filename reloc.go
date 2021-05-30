package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
)

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

// ApplyRelocations will apply relocations depending on the target binary.
// This step essentially processes symbolic references to their definitions.
func (p *Parser) ApplyRelocations(dst []byte, rels []byte) error {
	switch {
	case p.F.Class() == ELFCLASS64 && p.F.Machine == EM_X86_64:
		return p.applyRelocationsAMD64(dst, rels)
	default:
		return errors.New("not implemented")
	}
}

// applyRelocationsAMD64 applies relocatons to dst where rels is a relocations section
// for AMD64 (64-bit binaries & x86-64 machine types).
func (p *Parser) applyRelocationsAMD64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}
	symbols, _, err := p.getSymbols64(SHT_SYMTAB)
	if err != nil {
		return err
	}
	b := bytes.NewReader(rels)
	var rela Rela64
	for b.Len() > 0 {
		binary.Read(b, p.F.ByteOrder(), &rela)
		symNo := rela.Info >> 32
		t := R_X86_64(rela.Info & 0xffff)
		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).
		switch t {
		case R_X86_64_64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			p.F.ByteOrder().PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_X86_64_32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			p.F.ByteOrder().PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}
	return nil
}
