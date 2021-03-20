package elf

// FileHeader is an in-memory representation of the raw elf header.
type FileHeader struct{}

// File is an in-memory iterable representation of a raw elf binary
type File struct {
	FileHeader FileHeader
}
