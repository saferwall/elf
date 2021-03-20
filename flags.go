package elf

// Indexes in Ident array.
const (
	EI_CLASS      = 4  // Class of machine.
	EI_DATA       = 5  // Data format.
	EI_VERSION    = 6  // ELF format version.
	EI_OSABI      = 7  // Operating system / ABI identification
	EI_ABIVERSION = 8  // ABI version
	EI_PAD        = 9  // Start of padding (per SVR4 ABI).
	EI_NIDENT     = 16 // Size of e_ident array.
)

// Class takes values of 1 or 2 depending on the architecture 32-bit or 64-bit.
type Class byte

const (
	// ELFCLASSNONE specifies an unknown class.
	ELFCLASSNONE Class = 0
	// ELFCLASS32 specifies 32-bit binaries.
	ELFCLASS32 Class = 1
	// ELFCLASS64 specifies 64-bit binaries.
	ELFCLASS64 Class = 2
)

// Data takes values of 1 or 2 depending on whether its a little endian or big endian architecture.
type Data byte

const (
	// ELFDATANONE specifes an unknown architecture.
	ELFDATANONE Data = 0
	// DATA2LSB specifies a little-endian architecture.
	ELFDATA2LSB Data = 1
	// ELFDATA2MSB specifies a big-endian architecture.
	ELFDATA2MSB Data = 2
)

// Version specifies the current ELF version.
type Version byte

const (
	// EV_NONE specifes an unknown version.
	EV_NONE Version = 0
	// EV_CURRENT specifies the only current elf version equal to 1.
	EV_CURRENT Version = 1
)

// OSABI specifes the OS ABI version.
type OSABI byte

const (
	ELFOSABI_NONE       OSABI = 0   // UNIX System V ABI
	ELFOSABI_HPUX       OSABI = 1   // HP-UX operating system
	ELFOSABI_NETBSD     OSABI = 2   // NetBSD
	ELFOSABI_LINUX      OSABI = 3   // GNU/Linux
	ELFOSABI_HURD       OSABI = 4   // GNU/Hurd
	ELFOSABI_86OPEN     OSABI = 5   // 86Open common IA32 ABI
	ELFOSABI_SOLARIS    OSABI = 6   // Solaris
	ELFOSABI_AIX        OSABI = 7   // AIX
	ELFOSABI_IRIX       OSABI = 8   // IRIX
	ELFOSABI_FREEBSD    OSABI = 9   // FreeBSD
	ELFOSABI_TRU64      OSABI = 10  // TRU64 UNIX
	ELFOSABI_MODESTO    OSABI = 11  // Novell Modesto
	ELFOSABI_OPENBSD    OSABI = 12  // OpenBSD
	ELFOSABI_OPENVMS    OSABI = 13  // Open VMS
	ELFOSABI_NSK        OSABI = 14  // HP Non-Stop Kernel
	ELFOSABI_AROS       OSABI = 15  // Amiga Research OS
	ELFOSABI_FENIXOS    OSABI = 16  // The FenixOS highly scalable multi-core OS
	ELFOSABI_CLOUDABI   OSABI = 17  // Nuxi CloudABI
	ELFOSABI_ARM        OSABI = 97  // ARM
	ELFOSABI_STANDALONE OSABI = 255 // Standalone (embedded) application
)

// Type specifies the current binary type (Relocatable object file or Executable binary...)
type Type uint16

const (
	ET_NONE   Type = 0      // Unknown type.
	ET_REL    Type = 1      // Relocatable.
	ET_EXEC   Type = 2      // Executable.
	ET_DYN    Type = 3      // Shared object.
	ET_CORE   Type = 4      // Core file.
	ET_LOOS   Type = 0xfe00 // First operating system specific.
	ET_HIOS   Type = 0xfeff // Last operating system-specific.
	ET_LOPROC Type = 0xff00 // First processor-specific.
	ET_HIPROC Type = 0xffff // Last processor-specific.
)
