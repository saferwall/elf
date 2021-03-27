package main

import (
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
	fmt.Printf("%v", p.F.Header64)
	fmt.Println("VERY ELFY VERY COOL")

}
