`dwarf2json` is a Go utility that takes ELF or Mach-O files with DWARF as input and
generates [Volatilty3](https://github.com/volatilityfoundation/volatility3)
Intermediate Symbol File (ISF) JSON output.

Apple and several Linux distributions split debug DWARF information into
separate files.  `dwarf2json` is able to combine DWARF type information with symbol information from a mach-O or an ELF file.

To build (Go required):
```
  $ go build
```

To run:
```
  $ ./dwarf2json --help
```

To process macOS file:
```
  $ ./dwarf2json mac --dwarf /path/to/dwarf --macho /path/to/macho > output.json
```

To process Linux file:
```
  $ ./dwarf2json linux --dwarf /path/to/dwarf --elf /path/to/elf > output.json
```

When processing universal FAT binaries, the `-arch` flag needs to be used to
select the architecture for one of the embedded mach-O files. If `-arch` flag
is not passed, `x86_64` architecture will be selected by default. The flag is
ignored when processing other file types.

For example, generating ISF JSON file for i386 architecture in OS X 10.7
kernel debug kit can be done with:

```
  $ ./dwarf2json -arch i386 mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel > mach_kernel.json
```
