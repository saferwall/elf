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
	err = p.ParseHeader()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", p.F.FileHeader.Ident.Class)
	fmt.Printf("%s\n", p.F.FileHeader.Ident.OSABI)
	fmt.Printf("%s\n", p.F.FileHeader.Ident.Data)
	fmt.Printf("%s\n", p.F.FileHeader.Ident.ByteOrder)
	fmt.Printf("%s\n", p.F.FileHeader.Type)
	fmt.Printf("%s\n", p.F.FileHeader.Version)
	fmt.Printf("%s\n", p.F.FileHeader.Machine)
	fmt.Printf("%d\n", p.F.FileHeader.Size)
	fmt.Printf("%d\n", p.F.FileHeader.Entry)
	magic := p.F.FileHeader.Ident.Magic.String()

	if magic != elf.ELFMAG {
		fmt.Println("NOT AN ELF BINARY")
		return
	}
	fmt.Println(p.F.FileHeader.String())
	fmt.Println("VERY ELFY VERY COOL")

}
