# ELF File Format Parser 

-----

[![codecov](https://codecov.io/gh/saferwall/elf/branch/main/graph/badge.svg?token=ND685DTHZT)](https://codecov.io/gh/saferwall/elf) [![build-test](https://github.com/saferwall/elf/actions/workflows/ci.yaml/badge.svg)](https://github.com/saferwall/elf/actions/workflows/ci.yaml)

```elf``` is a lightweight :sparkles: ELF parser designed for static analysis.

## Install

You can install the ```elf``` package and its dependencies using the ```go get``` command.

```sh

go get github.com/saferwall/elf

```

## Usage

```go

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
	jsonFile, err := p.DumpJSON()
	if err != nil {
		panic(err)
	}
	fmt.Println(jsonFile)
}



```

## Docs & API

:construction: