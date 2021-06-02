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
	err = p.Parse()
	if err != nil {
		panic(err)
	}
	jsonFile, err := p.DumpJSON()
	if err != nil {
		panic(err)
	}
	fmt.Println(jsonFile)
}
