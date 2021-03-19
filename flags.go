package elf

// ELFClass takes values of 1 or 2 depending on the architecture 32-bit or 64-bit.
type ELFClass int

const (
	// ELFCLASS32 specifies 32-bit binaries.
	ELFCLASS32 = 1
	// ELFCLASS64 specifies 64-bit binaries.
	ELFCLASS64 = 2
)

// ELFEndianess takes values of 1 or 2 depending on whether its a little endian or big endian architecture.
type ELFEndianess int

const (
	// ELFDATA2LSB specifies a little-endian architecture.
	ELFDATA2LSB = 1
	// ELFDATA2MSB specifies a big-endian architecture.
	ELFDATA2MSB = 2
)

// ELFVersion specifies the current ELF version.
type ELFVersion int

const (
	// ELFCURRENT specifies the only current valid version equal to 1.
	ELFCURRENT = 1
)
