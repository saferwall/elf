<a href="https://saferwall.com" target="_blank" rel="noopener noreferrer"><img align="right" width="100" src=".github/assets/logo.png" alt="Saferwall logo"></a>

# ELF File Format Parser

[![GoDoc](http://godoc.org/github.com/saferwall/elf?status.svg)](https://pkg.go.dev/github.com/saferwall/elf) ![Go Version](https://img.shields.io/badge/go%20version-%3E=1.17-61CFDD.svg) [![Report Card](https://goreportcard.com/badge/github.com/saferwall/elf)](https://goreportcard.com/report/github.com/saferwall/elf) [![codecov](https://codecov.io/gh/saferwall/elf/branch/main/graph/badge.svg?token=ND685DTHZT)](https://codecov.io/gh/saferwall/elf) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/saferwall/elf/ci.yaml?branch=main)

**elf** is a go package for parsing Executable and Linkable Format (ELF). This package is designed for static malware analysis and reverse engineering.

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

## References

- https://refspecs.linuxfoundation.org/elf/elf.pdf
- https://github.com/freebsd/freebsd-src/blob/main/sys/sys/elf_common.h


