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
	err = p.Parse()
	if err != nil {
		panic(err)
	}
	jsonFile, err := json.MarshalIndent(p.F.ELFBin64, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonFile))
}
