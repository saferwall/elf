package elf

import (
	"encoding/json"
	"errors"
	"strings"
)

func dumpELF32(p *Parser, jsonOutput strings.Builder) (string, error) {
	jsonBin, err := json.MarshalIndent(p.F.ELFBin32, "", "  ")
	if err != nil {
		return "", err
	}
	jsonSymbols, err := json.MarshalIndent(p.F.ELFSymbols, "", " ")
	if err != nil {
		return "", err
	}
	_, err = jsonOutput.Write(jsonBin)
	if err != nil {
		return "", err
	}
	_, err = jsonOutput.Write(jsonSymbols)
	if err != nil {
		return "", err
	}
	return jsonOutput.String(), nil

}

func dumpELF64(p *Parser, jsonOutput strings.Builder) (string, error) {
	jsonBin, err := json.MarshalIndent(p.F.ELFBin64, "", "  ")
	if err != nil {
		return "", err
	}
	jsonSymbols, err := json.MarshalIndent(p.F.ELFSymbols, "", " ")
	if err != nil {
		return "", err
	}
	_, err = jsonOutput.Write(jsonBin)
	if err != nil {
		return "", err
	}
	_, err = jsonOutput.Write(jsonSymbols)
	if err != nil {
		return "", err
	}
	return jsonOutput.String(), nil
}

// DumpRawJSON marshals the raw binary representation into JSON Format.
func (p *Parser) DumpRawJSON() (string, error) {
	var jsonOutput strings.Builder

	switch p.F.Class() {
	case ELFCLASS32:
		return dumpELF32(p, jsonOutput)
	case ELFCLASS64:
		return dumpELF64(p, jsonOutput)
	default:
		return "", errors.New("unsupported ELF Class")
	}
}
