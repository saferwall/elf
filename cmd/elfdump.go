// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/saferwall/elf"
)

type config struct {
	wantELFFileHeader bool
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func dumpFileHeader(fileHdr elf.FileHeader) {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
	fmt.Print("\n\t------[ File Header ]------\n\n")
	fmt.Fprintf(w, "Magic:\t %v\n", fileHdr.Ident.Magic)
	fmt.Fprintf(w, "Class:\t %v\n", fileHdr.Ident.Class)
	fmt.Fprintf(w, "Data:\t %v\n", fileHdr.Ident.Data)
	fmt.Fprintf(w, "Version:\t %v\n", fileHdr.Ident.Version)
	fmt.Fprintf(w, "OS/ABI:\t %v\n", fileHdr.Ident.ABIVersion)
	fmt.Fprintf(w, "Type:\t %v\n", fileHdr.Type)
	fmt.Fprintf(w, "Machine:\t %v\n", fileHdr.Machine)
	fmt.Fprintf(w, "Version:\t %v\n", fileHdr.Version)
	fmt.Fprintf(w, "Entry point address :\t %v\n", fileHdr.Entry)
	fmt.Fprintf(w, "Start of program headers:\t %v\n", fileHdr.ProgramHeaderOffset)
	fmt.Fprintf(w, "Start of section headers:\t %v\n", fileHdr.SectionHeaderOffset)
	fmt.Fprintf(w, "Flags:\t %v\n", fileHdr.Flags)
	fmt.Fprintf(w, "Size of this header:\t %v\n", fileHdr.Size)
	fmt.Fprintf(w, "Size of program headers:\t %v\n", fileHdr.ProgramHeaderEntrySize)
	fmt.Fprintf(w, "Number of program headers:\t %v\n", fileHdr.ProgramHeaderNum)
	fmt.Fprintf(w, "Size of section headers:\t %v\n", fileHdr.SectionHeaderEntrySize)
	fmt.Fprintf(w, "Number of section headers:\t %v\n", fileHdr.SectionHeaderNum)
	fmt.Fprintf(w, "Section header string table index:\t %v\n", fileHdr.SectionHeaderStringIdx)
	w.Flush()
}

func parse(filename string, cfg config) {
	p, err := elf.New(filename, nil)
	defer p.CloseFile()
	if err != nil {
		panic(err)
	}
	err = p.Parse()
	if err != nil {
		panic(err)
	}

	if cfg.wantELFFileHeader {
		dumpFileHeader(p.F.FileHeader)
	}
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "This is not helpful.\n")
	}
	dumpCmd := flag.NewFlagSet("dump", flag.ExitOnError)
	dumpELFFileHdr := dumpCmd.Bool("file-header", false, "Display the ELF file header")
	verCmd := flag.NewFlagSet("version", flag.ExitOnError)

	if len(os.Args) < 2 {
		showHelp(nil)
	}

	switch os.Args[1] {

	case "dump":
		var filename string
		for _, arg := range os.Args[2:] {
			if !strings.HasPrefix(arg, "-") {
				filename = arg
			}
		}
		if len(filename) == 0 {
			showHelp(dumpCmd)
		}

		if err := dumpCmd.Parse(os.Args[2:]); err != nil {
			showHelp(dumpCmd)
		}

		cfg := config{
			wantELFFileHeader: *dumpELFFileHdr,
		}

		parse(filename, cfg)

	case "version":
		verCmd.Parse(os.Args[2:])
		fmt.Println("You are using version 0.4.0")
	default:
		showHelp(nil)
	}
}

func showHelp(cmd *flag.FlagSet) {
	fmt.Print(
		`
			┏┓┏┓┏┓┏┓┳┓┓ ┏┏┓┓ ┓
			┗┓┣┫┣ ┣ ┣┫┃┃┃┣┫┃ ┃
			┗┛┛┗┻ ┗┛┛┗┗┻┛┛┗┗┛┗┛
			┏┓┓ ┏┓  ┏┓┏┓┳┓┏┓┏┓┳┓
			┣ ┃ ┣   ┃┃┣┫┣┫┗┓┣ ┣┫
			┗┛┗┛┻   ┣┛┛┗┛┗┗┛┗┛┛┗


	An ELF Parser built for speed and malware-analysis in mind.
	Brought to you by Saferwall (c) 2018 Apache-2.0
`)
	if cmd == nil {
		fmt.Println("\nAvailable sub-commands 'dump' or 'version' subcommands !")
	} else {
		fmt.Println("\nUsage: elfdump <option(s)> elf-file(s)\nOptions are:")
		cmd.PrintDefaults()
	}

	os.Exit(1)
}
