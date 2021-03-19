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
	magicBytes, err := p.ReadMagicBytes()
	if err != nil {
		panic(err)
	}
	magic := string(magicBytes)

	if magic != elf.ELFMAG {
		fmt.Println("NOT AN ELF BINARY")
		return
	}
	fmt.Println("VERY ELFY VERY COOL")

}
