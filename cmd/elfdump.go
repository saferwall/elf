package main

import (
	"encoding/json"
	"fmt"

	"github.com/saferwall/elf"
)

func main() {

	p, err := elf.New("/bin/ls")
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	err = p.ParseIdent()
	if err != nil {
		panic(err)
	}
	magic := p.F.Ident.Magic.String()

	if magic != elf.ELFMAG {
		fmt.Println("NOT AN ELF BINARY")
		return
	}
	err = p.ParseELFHeader(p.F.Class())
	if err != nil {
		panic(err)
	}
	fmt.Println("VERY ELFY VERY COOL")
	jsonHeader, err := json.MarshalIndent(p.F.Header64, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonHeader))

	err = p.ParseELFSectionHeader(elf.ELFCLASS64)
	if err != nil {
		panic(err)
	}
	jsonHeader, err = json.MarshalIndent(p.F.SectionHeaders, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonHeader))
}
