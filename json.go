package elf

import (
	"encoding/json"
	"errors"
	"strings"
)

// DumpRawJSON marshals the raw binary representation into JSON Format.
func (p *Parser) DumpRawJSON() (string, error) {

	var jsonOutput strings.Builder

	switch p.F.Class() {
	case ELFCLASS32:
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
	case ELFCLASS64:
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
	default:
		return "", errors.New("unsupported ELF Class")
	}
}
