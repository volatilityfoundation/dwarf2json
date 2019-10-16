# Introduction

`dwarf2json` is a Go utility that processes files containing symbol and type
information to generate [Volatilty3](https://github.com/volatilityfoundation/volatility3)
Intermediate Symbol File (ISF) JSON output suitable for Linux and macOS
analysis.

To build (Go 1.13+ required):
```
  $ go build
```

To run:
```
  $ ./dwarf2json --help
  Usage: ./dwarf2json COMMAND

  A tool for generating intermediate symbol file (ISF)

  Commands:
    linux  generate ISF for Linux analysis
    mac    generate ISF for macOS analysis
```

# Linux Processing
`dwarf2json` supports processing DWARF and symbol table information from ELF
files and symbols from System.map input files to produce ISF for
Linux analysis.

The user is able to select whether to include symbol, type, or both for each
input file.

```
  $ ./dwarf2json linux --help
  Usage: dwarf2json linux [OPTIONS]

        --elf PATH           ELF file PATH to extract symbol and type information
        --elf-symbols PATH   ELF file PATH to extract only symbol information
        --elf-types PATH     ELF file PATH to extract only type information
        --system-map PATH    System.Map file PATH to extract symbol information
```

For example, to include symbols and types for a given Linux kernel DWARF
file can be done with:
```
  $ ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-4.4.0-137-generic > output.json
```

Symbol offsets for symbols extracted from symbol table information take
precedence over those extracted from DWARF information. Thus, symbols extracted
from files specified with `--elf-symbols` flag take precedence over symbols
extracted from files specified with `--elf`. Symbol offsets for symbols from
`System.Map`, specified with `--system-map` flag, are the highest precedence. If
there is a conflict between the different symbol information sources, the
offset from `System.Map` will be used.

Providing multiple input files for a given flag is allowed. For example,
`./dwarf2json --elf file1 --elf file2 ...` would process both `file1` and
`file2`. When conflicting symbol or type information is encountered, the data
from the last file specified in the command invocation would take precedence.

# MacOS Processing
`dwarf2json` supports processing DWARF and symbol table information from Mach-O
files to produce ISF for macOS analysis.

The user is able to select whether to include symbol, type, or both for each
input file.

```
  $ ./dwarf2json mac --help
  Usage: dwarf2json mac [OPTIONS]

        --arch NAME            architecture for universal FAT files. NAME is one of {i386|x86_64}
        --macho PATH           Mach-O file PATH to extract symbol and type information
        --macho-symbols PATH   Mach-O file PATH to extract only symbol information
        --macho-types PATH     Mach-O file PATH to extract only type information
```

For example, to include symbols and types for a given macOS kernel DWARF
file and symbols from a macOS kernel can be done with:
```
  $ ./dwarf2json mac --macho /path/kernel.dSYM/Contents/Resources/DWARF/kernel \
    --macho-symbols /path/kernel > output.json
```

Symbol offsets for symbols extracted from symbol table information take
precedence over those extracted from DWARF information. Thus, symbols extracted
from files specified with `--macho-symbols` flag take precedence over symbols
extracted from files specified with `--macho`.


Providing multiple input files for a given flag is allowed. For example,
`./dwarf2json --macho file1 --macho file2 ...` would process both `file1` and
`file2`. When conflicting symbol or type information is encountered, the data
from the last file specified in the command invocation would take precedence.

When processing Mach-O universal FAT binaries, the `--arch` flag needs to be
used to select the architecture for one of the embedded Mach-O files.

For example, generating ISF JSON file for i386 architecture of a OS X 10.7
kernel debug kit can be done with:

```
  $ ./dwarf2json mac --arch i386 \
  --macho mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel \
  --macho-symbols mach_kernel > mach_kernel.json
```
