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
	fmt.Printf("%s\n", p.F.Ident.Class)
	fmt.Printf("%s\n", p.F.Ident.OSABI)
	fmt.Printf("%s\n", p.F.Ident.Data)
	fmt.Printf("%s\n", p.F.Ident.ByteOrder)
	fmt.Printf("%s\n", p.F.Header.Type)
	fmt.Printf("%s\n", p.F.Header.Version)
	fmt.Printf("%s\n", p.F.Header.Machine)
	fmt.Printf("%d\n", p.F.Header.Size)
	fmt.Printf("%d\n", p.F.Header.Entry)
	magic := p.F.Ident.Magic.String()

	if magic != elf.ELFMAG {
		fmt.Println("NOT AN ELF BINARY")
		return
	}
	fmt.Println(p.F.Header.PrettyString())
	fmt.Println("VERY ELFY VERY COOL")

}
