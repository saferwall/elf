// Package elf : stringer.go implements various string related utilites
// and stringer interface implementation for all custom types.
package elf

import "strconv"

// flagName pairs integer flags and a corresponding string.
type flagName struct {
	flag uint32
	name string
}

// stringify matches various elf flags against their naming maps.
func stringify(flag uint32, names []flagName, goSyntax bool) string {

	for _, n := range names {
		if n.flag == flag {
			if goSyntax {
				return "elf." + n.name
			}
			return n.name
		}
	}

	for j := len(names) - 1; j >= 0; j-- {
		n := names[j]
		if n.flag < flag {
			name := n.name
			if goSyntax {
				name = "elf." + name
			}
			return name + "+" + strconv.FormatUint(uint64(flag-n.flag), 10)
		}
	}

	return strconv.FormatUint(uint64(flag), 10)
}

// matchFlagName matches a given integer flag against it's corresponding flagname.
func matchFlagName(flag uint32, names []flagName, goSyntax bool) string {
	s := ""
	for _, n := range names {
		if n.flag&flag == n.flag {
			if len(s) > 0 {
				s += "+"
			}
			if goSyntax {
				s += "elf."
			}
			s += n.name
			flag -= n.flag
		}
	}
	if len(s) == 0 {
		return "0x" + strconv.FormatUint(uint64(flag), 16)
	}
	if flag != 0 {
		s += "+0x" + strconv.FormatUint(uint64(flag), 16)
	}
	return s
}
