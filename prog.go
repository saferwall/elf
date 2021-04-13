package elf

// ELFProgramHeader64 represents the program header table which is an array
// entries describing each program segment (in executable or shared object files)
// sections are grouped into segments for in-memory loading.
type ELF64ProgramHeader64 struct {
	Type   uint32 // Segment type
	Flags  uint32 // Segment attributes
	Off    uint64 // Offset in file
	Vaddr  uint64 // Virtual Address in memory
	Paddr  uint64 // Reserved
	Filesz uint64 // Size of segment in file
	Memsz  uint64 // Size of segment in memory
	Align  uint64 // Segment alignment
}
