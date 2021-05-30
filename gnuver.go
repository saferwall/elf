// Package elf: gnuver.go implements the GNU Version table specification.
package elf

import "errors"

// GNUVersion holds the version information
type GNUVersion struct {
	File string
	Name string
}

// ImportedSymbol will hold information on external imports.
type ImportedSymbol struct {
	Name    string
	Version string
	Library string
}

// ParseGNUVersionTable parses the GNU version tables.
func (p *Parser) ParseGNUVersionTable(str []byte) error {
	if p.F.GNUVersion != nil {
		return errors.New("already processed GNU version table")
	}

	vn := p.F.GetSectionByType(SHT_GNU_VERNEED)
	if vn == nil {
		return errors.New("no gnu verneed section in file")
	}
	d, _ := vn.Data()

	var gnuVer []GNUVersion
	i := 0
	for {
		if i+16 > len(d) {
			break
		}
		vers := p.F.ByteOrder().Uint16(d[i : i+2])
		if vers != 1 {
			break
		}
		cnt := p.F.ByteOrder().Uint16(d[i+2 : i+4])
		fileoff := p.F.ByteOrder().Uint32(d[i+4 : i+8])
		aux := p.F.ByteOrder().Uint32(d[i+8 : i+12])
		next := p.F.ByteOrder().Uint32(d[i+12 : i+16])
		file, _ := getString(str, int(fileoff))

		var name string

		j := i + int(aux)
		for c := 0; c < int(cnt); c++ {
			if j+16 > len(d) {
				break
			}
			other := p.F.ByteOrder().Uint16(d[j+6 : j+8])
			nameoff := p.F.ByteOrder().Uint32(d[j+8 : j+12])
			next := p.F.ByteOrder().Uint32(d[j+12 : j+16])
			name, _ = getString(str, int(nameoff))
			ndx := int(other)
			if ndx >= len(gnuVer) {
				a := make([]GNUVersion, 2*(ndx+1))
				copy(a, gnuVer)
				gnuVer = a
			}
			gnuVer[ndx] = GNUVersion{file, name}
			if next == 0 {
				break
			}
			j += int(next)
		}
		if next == 0 {
			break
		}
		i += int(next)

	}
	// Versym parallels symbol table, indexing into verneed.
	vs := p.F.GetSectionByType(SHT_GNU_VERSYM)
	if vs == nil {
		return errors.New("no gnu versym section in file")
	}
	d, _ = vs.Data()
	p.F.GNUVersion = gnuVer
	p.F.GNUVersionSym = d
	return nil

}

// gnuVersion adds Library and Version information to namedSymbol,
// which came from offset i of the symbol table.
func (p *Parser) gnuVersion(i int) (string, string) {
	// Each entry is two bytes.
	i = (i + 1) * 2
	if i >= len(p.F.GNUVersionSym) {
		return "", ""
	}
	j := int(p.F.ByteOrder().Uint16(p.F.GNUVersionSym[i:]))
	if j < 2 || j >= len(p.F.GNUVersion) {
		return "", ""
	}
	n := &p.F.GNUVersion[j]
	return n.File, n.Name
}
