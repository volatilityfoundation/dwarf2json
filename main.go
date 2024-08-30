// This file is Copyright 2019 Volatility Foundation, Inc. and licensed under
// the Volatility Software License 1.0, which is available at
// https://www.volatilityfoundation.org/license/vsl-v1.0

// utility for converting DWARF in ELF to JSON

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

const (
	DW_OP_addr = 0x3
)

const (
	TOOL_NAME      = "dwarf2json"
	TOOL_VERSION   = "0.8.0"
	FORMAT_VERSION = "6.2.0"
)

// Extract defines the type/symbol information that should be processed
type Extract int

// Defines information to extract during processing steps
const (
	DwarfSymbols  Extract = 1
	DwarfTypes    Extract = 2
	SymTabSymbols Extract = 4
	ConstantData  Extract = 8
	SystemMap     Extract = 16
)

// DW_AT_language bindings
const (
	DW_LANG_Rust = 0x1c
)

// FileToProcess defines the file that needs to be processed and
// information that should be extracted from that file
type FileToProcess struct {
	FilePath string
	Extract  Extract
}

// FilesToProcess is a list of file that need processing
type FilesToProcess []FileToProcess

// Add intelligently adds a file to processing queue
func (f *FilesToProcess) Add(newFile FileToProcess) {
	// if file path of the new file exists, then update what needs to be done
	for i := range *f {
		if (*f)[i].FilePath == newFile.FilePath {
			(*f)[i].Extract |= newFile.Extract
			return
		}
	}

	// else add a new entry
	*f = append(*f, newFile)
}

// The symbol names are part of Linux's or Mac's read-only data
// Their contents will be saved, if the symbol is found
var constantLinuxDataSymbols = []string{"linux_banner"}
var constantMacosDataSymbols = []string{"version"}

// The compiler can add a leading underscore to symbol names in the symbol
// table. To match the names from a mach-O file to those in the DWARF file, the
// symbol from the mach-O file may need to be stripped of the leading
// underscore.
var stripLeadingUnderscore = false

// sha256Sum computes sha256 hash of filePath
func sha256Sum(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil

}

type sourceMetadata struct {
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	HashType  string `json:"hash_type,omitempty"`
	HashValue string `json:"hash_value,omitempty"`
}

func newSourceMetadata(filePath string) *sourceMetadata {
	fileMeta := &sourceMetadata{Name: filepath.Base(filePath)}
	sha, err := sha256Sum(filePath)
	if err == nil {
		fileMeta.HashType = "sha256"
		fileMeta.HashValue = fmt.Sprintf("%x", sha)
	}
	return fileMeta
}

type unixMetadata struct {
	Symbols []*sourceMetadata `json:"symbols,omitempty"`
	Types   []*sourceMetadata `json:"types,omitempty"`
}

type vtypeMetadata struct {
	Linux    *unixMetadata     `json:"linux,omitempty"`
	Mac      *unixMetadata     `json:"mac,omitempty"`
	Producer map[string]string `json:"producer"`
	Format   string            `json:"format"`
}

// newVtypeMetadata created a new vtypeMetadata structure containing meta-data
// about the ISF file being produced.
func newVtypeMetadata() *vtypeMetadata {
	result :=
		&vtypeMetadata{
			Producer: make(map[string]string),
			Format:   FORMAT_VERSION,
		}

	result.Producer["version"] = TOOL_VERSION
	result.Producer["name"] = TOOL_NAME
	return result
}

type vtypeStructField struct {
	FieldType map[string]interface{} `json:"type,omitempty"`
	Offset    int64                  `json:"offset"`
	Anonymous bool                   `json:"anonymous,omitempty"`
}

type vtypeStruct struct {
	Size   int64                       `json:"size"`
	Fields map[string]vtypeStructField `json:"fields"`
	Kind   string                      `json:"kind"`
}

type vtypeBaseType struct {
	Size   int64  `json:"size"`
	Signed bool   `json:"signed"`
	Kind   string `json:"kind"`
	Endian string `json:"endian"`
}

type vtypeEnum struct {
	Size      int64            `json:"size"`
	Base      string           `json:"base"`
	Constants map[string]int64 `json:"constants"`
}

type vtypeSymbol struct {
	SymbolType   map[string]interface{} `json:"type,omitempty"`
	Address      uint64                 `json:"address"`
	ConstantData []byte                 `json:"constant_data,omitempty"`
}

func newVtypeJson() *vtypeJson {
	return &vtypeJson{
		Metadata:  newVtypeMetadata(),
		BaseTypes: make(map[string]*vtypeBaseType),
		UserTypes: make(map[string]*vtypeStruct),
		Enums:     make(map[string]*vtypeEnum),
		Symbols:   make(map[string]*vtypeSymbol),
	}
}

type vtypeJson struct {
	Metadata  *vtypeMetadata            `json:"metadata"`
	BaseTypes map[string]*vtypeBaseType `json:"base_types"`
	UserTypes map[string]*vtypeStruct   `json:"user_types"`
	Enums     map[string]*vtypeEnum     `json:"enums"`
	Symbols   map[string]*vtypeSymbol   `json:"symbols"`
}

func (doc *vtypeJson) addStruct(structType *dwarf.StructType, name, endian string, off dwarf.Offset, codeNs string) error {
	if structType.Incomplete {
		return nil
	}

	st :=
		&vtypeStruct{
			Size:   structType.Size(),
			Fields: make(map[string]vtypeStructField),
			Kind:   structType.Kind,
		}

	anonymousCount := 0
	for _, field := range structType.Field {
		if field == nil {
			continue
		}

		fieldType := typeName(field.Type, codeNs)

		// skip fields for which type cannot be obtained
		if fieldType == nil {
			continue
		}

		vtypeField := vtypeStructField{Offset: field.ByteOffset}
		fieldName := field.Name
		if fieldName == "" {
			fieldName = fmt.Sprintf("unnamed_field_%x", anonymousCount)
			vtypeField.Anonymous = true
			anonymousCount += 1
		}

		if field.BitSize != 0 {
			vtypeField.FieldType = make(map[string]interface{})
			vtypeField.FieldType["kind"] = "bitfield"
			vtypeField.FieldType["bit_length"] = field.BitSize
			vtypeField.FieldType["type"] = fieldType

			var bitOffset int64
			var byteOffset int64 = field.ByteOffset

			// DWARF4 introduced a new attribute for describing bitfields,
			// DW_AT_data_bit_offset. This is exposed by the debug/dwarf
			// library as FieldType.DataBitOffset. This new field replaces the
			// old FieldType.BitOffset for DWARF versions >= 5.

			// According the the debug/dwarf library, the field with a value >
			// 0 should be used. However this is not enough because there are
			// cases where both fields can be zero at the same time.

			// Because of this ambiguity, field.ByteSize is used as a heuristic
			// to decide between which field to use. The FieldType.ByteSize is
			// > 0, when FieldType.BitOffset is used.
			if field.ByteSize > 0 {
				// assume Dwarf <=4
				if field.DataBitOffset > 0 {
					return fmt.Errorf("bitfield heuristic violated at offset %v because DataBitOffset > 0", off)
				}

				bitOffset = field.BitOffset
				if endian == "little" {
					// calculation to change the DWARF offset from MSB to LSB
					bitOffset = 8*field.ByteSize - (field.BitOffset + field.BitSize)
				}
				byteOffset += bitOffset / 8
				bitOffset %= 8
			} else {
				// assuming DWARF version > 4
				if field.BitOffset > 0 {
					return fmt.Errorf("bitfield heuristic violated at offset %v because BitOffset > 0", off)
				}
				byteOffset = field.DataBitOffset / 8
				bitOffset = field.DataBitOffset % 8
			}

			vtypeField.Offset = byteOffset
			vtypeField.FieldType["bit_position"] = bitOffset

		} else {
			vtypeField.FieldType = fieldType
		}

		st.Fields[fieldName] = vtypeField
	}

	doc.UserTypes[name] = st

	return nil
}

func (doc *vtypeJson) addDwarf(data *dwarf.Data, endian string, extract Extract) error {

	doc.BaseTypes["void"] = &vtypeBaseType{Size: 0, Signed: false, Kind: "void", Endian: endian}

	symbolsCb := func(entry *dwarf.Entry, addressSize int, codeNs string) error {
		switch entry.Tag {
		case dwarf.TagVariable:
			name, _ := entry.Val(dwarf.AttrName).(string)
			typOff, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)
			loc := entry.AttrField(dwarf.AttrLocation)
			if name == "" || typOff == 0 {
				// if entry.Val(dwarf.AttrSpecification) != nil {
				//     // Since we are reading all the DWARF,
				//     // assume we will see the variable elsewhere.
				//     break
				// }
				break
				// return fmt.Errorf("malformed DWARF TagVariable entry")
			}

			var address uint64
			// insert 0 when we don't know the address. ELF symbol table
			// may know it...
			if loc == nil {
				address = 0
			} else {
				address = locationToUint64(loc, addressSize)
			}
			sym := &vtypeSymbol{Address: address}
			genericType, err := data.Type(typOff)
			if err == nil {
				sym.SymbolType = typeName(genericType, codeNs)
			} else {
				voidType := make(map[string]interface{}, 0)
				voidType["kind"] = "base"
				voidType["name"] = "void"
				sym.SymbolType = voidType
			}
			doc.Symbols[codeNs+name] = sym
		}
		return nil

	}

	typesCb := func(entry *dwarf.Entry, addressSize int, codeNs string) error {
		switch entry.Tag {
		case dwarf.TagUnionType:
			fallthrough
		case dwarf.TagStructType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			structType, ok := genericType.(*dwarf.StructType)
			if ok != true {
				return fmt.Errorf("%s is not a StructType?", genericType.String())
			}
			err = doc.addStruct(structType, structName(structType, codeNs), endian, entry.Offset, codeNs)
			if err != nil {
				return fmt.Errorf("could not parse struct: %s", err)
			}
		case dwarf.TagEnumerationType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			enumType, ok := genericType.(*dwarf.EnumType)
			if ok != true {
				return fmt.Errorf("%s is not an EnumType?", genericType.String())
			}
			et :=
				&vtypeEnum{
					Size:      enumType.ByteSize,
					Base:      "void", // replaced below, if match found
					Constants: make(map[string]int64, 0),
				}

			if et.Size < 0 {
				et.Size = 0
			}

			enumSigned := false
			for _, v := range enumType.Val {
				et.Constants[v.Name] = v.Val
				if v.Val < 0 {
					enumSigned = true
				}
			}

			// Sort keys to make map enum type selection deterministic
			keys := make([]string, 0, len(doc.BaseTypes))
			for k := range doc.BaseTypes {
				// Avoid inserting language typed baseTypes in the (default) non-typed
				// C baseTypes pool.
				if codeNs == "" {
					if !strings.Contains(k, ".") {
						keys = append(keys, k)
					}
				} else if strings.HasPrefix(k, codeNs) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			// Now match type using sorted keys
			for _, baseName := range keys {
				baseType := doc.BaseTypes[baseName]
				if baseType.Kind == "int" && baseType.Size == enumType.ByteSize && baseType.Signed == enumSigned {
					et.Base = baseName
					break
				}
			}

			doc.Enums[enumName(enumType, codeNs)] = et
		case dwarf.TagPointerType:
			if _, present := doc.BaseTypes[codeNs+"pointer"]; !present {
				genericType, err := data.Type(entry.Offset)
				if err != nil {
					break
				}
				doc.BaseTypes[codeNs+"pointer"] =
					&vtypeBaseType{Size: genericType.Size(), Signed: false, Kind: "int", Endian: endian}
			}
		case dwarf.TagBaseType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			common := genericType.Common()
			if _, present := doc.BaseTypes[codeNs+common.Name]; !present {
				doc.BaseTypes[codeNs+common.Name] = newBasetype(genericType, endian)
			}
		case dwarf.TagTypedef:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}

			typedefType, ok := genericType.(*dwarf.TypedefType)
			if !ok {
				break
			}

			if structType, ok := typedefType.Type.(*dwarf.StructType); ok && structType.Name == "" {
				err := doc.addStruct(structType, codeNs+typedefType.Name, endian, entry.Offset, codeNs)
				if err != nil {
					return fmt.Errorf("could not parse struct: %s", err)
				}
			}

		}
		return nil
	}

	callBacks := []func(entry *dwarf.Entry, addressSize int, codeNs string) error{}

	if extract&DwarfTypes != 0 {
		callBacks = append(callBacks, typesCb)
	}
	if extract&DwarfSymbols != 0 {
		callBacks = append(callBacks, symbolsCb)
	}

	// Initialize namespace prefix to an empty string
	codeNs := ""
	// go through the DWARF
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if entry == nil && err == nil {
			// fmt.Printf("Done!\n")
			break
		}

		if err != nil {
			return err
		}

		/* Check if this entry is a compile unit.
		This will mark all children of this CU with
		the corresponding prefix ("<language>.").
		The goal is to avoid conflicts between common names (structs, symbols...)
		accross multiple languages, by prefixing objects with a namespace. */
		if entry.Tag == dwarf.TagCompileUnit {
			// Detect RUST language, needed for Linux kernel 6.5+
			if entry.Val(dwarf.AttrLanguage).(int64) == DW_LANG_Rust {
				codeNs = "rust."
			} else {
				// Default to an empty string for other languages (C mostly).
				// Avoid trying to specifically detect C language
				// to prevent edge cases.
				codeNs = ""
			}
		}

		for _, cb := range callBacks {
			err = cb(entry, reader.AddressSize(), codeNs)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// This is a very dumbed-down dwarf expression evaluator.
// For now we only support addresses...
func computeDwarfExpression(buf []byte, addressSize int) (uint64, error) {
	if len(buf) < 5 {
		return 0, fmt.Errorf("not enough data to compute expression (%d bytes)", len(buf))
	}

	if buf[0] != DW_OP_addr {
		return 0, fmt.Errorf("unsupported DWARF opcode 0x%x", buf[0])
	}

	var retval uint64
	var err error
	reader := bytes.NewReader(buf[1:])
	if addressSize == 4 {
		var retval32 uint32

		err = binary.Read(reader, binary.LittleEndian, &retval32)
		retval = uint64(retval32)
	} else {
		err = binary.Read(reader, binary.LittleEndian, &retval)
	}

	if err != nil {
		return 0, err
	}

	return retval, nil
}

func locationToUint64(loc *dwarf.Field, addressSize int) uint64 {
	var result uint64

	switch loc.Class {
	default:
		// fmt.Printf("WARNING: unconverted location %v\n", loc.Class)
	case dwarf.ClassAddress:
		result = loc.Val.(uint64)
	case dwarf.ClassConstant:
		result = uint64(loc.Val.(int64))
	// case dwarf.ClassLocListPtr:
	//     fmt.Printf("loclistptr: 0x%x\n", loc.Val.(int64))
	case dwarf.ClassExprLoc:
		val, err := computeDwarfExpression(loc.Val.([]byte), addressSize)
		if err == nil {
			result = val
		} else {
			// fmt.Printf("WARNING: failed to compute DWARF location expression: %v\n", err)
		}
	}

	return result
}

func structName(dwarfStruct *dwarf.StructType, codeNs string) string {
	if dwarfStruct.StructName != "" {
		return codeNs + dwarfStruct.StructName
	}

	data := sha1.Sum([]byte(dwarfStruct.Defn()))
	return fmt.Sprintf("unnamed_%8x", data[0:8])
}

func enumName(dwarfEnum *dwarf.EnumType, codeNs string) string {
	if dwarfEnum.EnumName != "" {
		return codeNs + dwarfEnum.EnumName
	}

	data := sha1.Sum([]byte(dwarfEnum.String()))
	return fmt.Sprintf("unnamed_%8x", data[0:8])
}

func typeName(dwarfType dwarf.Type, codeNs string) map[string]interface{} {
	result := make(map[string]interface{}, 0)

	switch t := dwarfType.(type) {
	case *dwarf.StructType:
		result["kind"] = t.Kind
		result["name"] = structName(t, codeNs)
	case *dwarf.ArrayType:
		result["kind"] = "array"
		if t.Count < 0 {
			result["count"] = 0
		} else {
			result["count"] = t.Count
		}
		result["subtype"] = typeName(t.Type, codeNs)
	case *dwarf.PtrType:
		result["kind"] = "pointer"
		result["subtype"] = typeName(t.Type, codeNs)
	case *dwarf.EnumType:
		result["kind"] = "enum"
		result["name"] = enumName(t, codeNs)
	case *dwarf.BoolType, *dwarf.CharType, *dwarf.ComplexType, *dwarf.IntType, *dwarf.FloatType, *dwarf.UcharType, *dwarf.UintType:
		result["kind"] = "base"
		result["name"] = codeNs + t.Common().Name
	case *dwarf.TypedefType:
		if structType, ok := t.Type.(*dwarf.StructType); ok && structType.Name == "" {
			result["kind"] = structType.Kind
			result["name"] = codeNs + t.Name
		} else {
			result = typeName(t.Type, codeNs)
		}
	case *dwarf.QualType:
		result = typeName(t.Type, codeNs)
	case *dwarf.VoidType, *dwarf.UnspecifiedType:
		result["kind"] = "base"
		result["name"] = "void"
	case *dwarf.FuncType:
		result["kind"] = "function"
	// *dwarf.UnsupportedType:
	default:
		return nil
	}

	return result
}

func newBasetype(dwarfType dwarf.Type, endian string) *vtypeBaseType {
	signed := true
	kind := "int"

	switch dwarfType.(type) {
	case *dwarf.UintType:
		signed = false
	case *dwarf.UcharType:
		signed = false
		kind = "char"
	case *dwarf.CharType:
		kind = "char"
	case *dwarf.BoolType:
		kind = "bool"
	case *dwarf.FloatType:
		kind = "float"
	}

	bt :=
		&vtypeBaseType{
			Size:   dwarfType.Size(),
			Signed: signed,
			Kind:   kind,
			Endian: endian,
		}

	return bt
}

func readELFSymbol(file *elf.File, symbol elf.Symbol) ([]byte, error) {
	var result []byte
	var err error

	for _, section := range file.Sections {
		if section.Name == ".rodata" &&
			(section.Flags&elf.SHF_ALLOC) == elf.SHF_ALLOC &&
			section.Addr <= symbol.Value &&
			(section.Addr+section.Size) >= (symbol.Value+symbol.Size) {

			start := symbol.Value - section.Addr
			end := start + symbol.Size
			sectionData, err := section.Data()
			if err == nil {
				result = sectionData[start:end]
			}

			break
		}

	}

	return result, err
}

func readMachoSymbol(file *macho.File, symbol macho.Symbol, length uint64) ([]byte, error) {
	var result []byte
	var err error

	for _, section := range file.Sections {
		if section.Name == "__const" && section.Addr <= symbol.Value &&
			(section.Addr+section.Size) >= (symbol.Value+length) {

			start := symbol.Value - section.Addr
			end := start + length
			sectionData, err := section.Data()
			if err == nil {
				result = sectionData[start:end]
			}

			break
		}

	}

	return result, err
}

func main() {

	// Help message setup
	pflag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %s COMMAND

A tool for generating intermediate symbol file (ISF)

Commands:
  linux  generate ISF for Linux analysis
  mac    generate ISF for macOS analysis

`,
			os.Args[0])
	}
	pflag.ErrHelp = errors.New("")

	// mac subcommand setup
	macArgs := pflag.NewFlagSet("mac", pflag.ExitOnError)
	fatArch := macArgs.String("arch", "", "architecture for universal FAT files. `NAME` is one of {i386|x86_64}")
	machoSymbolPaths := macArgs.StringArray("macho-symbols", nil, "Mach-O file `PATH` to extract only symbol information")
	machoTypePaths := macArgs.StringArray("macho-types", nil, "Mach-O file `PATH` to extract only type information")
	machoPaths := macArgs.StringArray("macho", nil, "Mach-O file `PATH` to extract symbol and type information")
	macArgs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s mac [OPTIONS]\n\n", TOOL_NAME)
		macArgs.PrintDefaults()
	}

	// linux subcommand setup
	linuxArgs := pflag.NewFlagSet("linux", pflag.ExitOnError)
	elfPaths := linuxArgs.StringArray("elf", nil, "ELF file `PATH` to extract symbol and type information")
	systemMapPaths := linuxArgs.StringArray("system-map", nil, "System.Map file `PATH` to extract symbol information")
	elfTypePaths := linuxArgs.StringArray("elf-types", nil, "ELF file `PATH` to extract only type information")
	elfSymbolPaths := linuxArgs.StringArray("elf-symbols", nil, "ELF file `PATH` to extract only symbol information")
	linuxArgs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s linux [OPTIONS]\n\n", TOOL_NAME)
		linuxArgs.PrintDefaults()
	}

	if len(os.Args) < 2 {
		pflag.Usage()
		os.Exit(0)
	}

	var err error
	var doc *vtypeJson

	// Switch on the subcommand
	switch os.Args[1] {
	case "mac":
		macArgs.Parse(os.Args[2:])

		var filesToProcess FilesToProcess

		// Type only
		for _, filePath := range *machoTypePaths {
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: DwarfTypes})
		}

		// Type and Symbols
		for _, filePath := range *machoPaths {
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: SymTabSymbols | DwarfSymbols | DwarfTypes | ConstantData})
		}

		//Symbol only
		for _, filePath := range *machoSymbolPaths {
			// filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: DwarfSymbols | SymTabSymbols | ConstantData})
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: SymTabSymbols | ConstantData})
		}

		if len(filesToProcess) == 0 {
			fmt.Fprintf(os.Stderr, "No files specified\n")
			macArgs.Usage()
			os.Exit(1)
		}

		doc, err = generateMac(filesToProcess, *fatArch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed mac processing: %v\n", err)
			os.Exit(1)
		}

	case "linux":
		linuxArgs.Parse(os.Args[2:])

		var filesToProcess FilesToProcess
		// Type only
		for _, filePath := range *elfTypePaths {
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: DwarfTypes})
		}

		// Type and Symbols
		for _, filePath := range *elfPaths {
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: SymTabSymbols | DwarfSymbols | DwarfTypes | ConstantData})
		}

		//Symbol only
		for _, filePath := range *elfSymbolPaths {
			// filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: DwarfSymbols | SymTabSymbols | ConstantData})
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: SymTabSymbols | ConstantData})
		}

		// System.Map processing
		for _, filePath := range *systemMapPaths {
			filesToProcess.Add(FileToProcess{FilePath: filePath, Extract: SystemMap})
		}

		if len(filesToProcess) == 0 {
			fmt.Fprintf(os.Stderr, "No files specified\n")
			linuxArgs.Usage()
			os.Exit(1)
		}

		doc, err = generateLinux(filesToProcess)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed linux processing: %v\n", err)
			os.Exit(1)
		}

	case "-h", "--help":
		pflag.Usage()
		os.Exit(0)
	default:
		fmt.Fprintf(
			os.Stderr,
			"%s: '%s' is not a %s command.\nSee '%s --help'\n",
			TOOL_NAME,
			os.Args[1],
			TOOL_NAME,
			TOOL_NAME,
		)
		os.Exit(1)
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(255)
	}
	os.Stdout.Write(b)
}

func generateMac(files FilesToProcess, fatArch string) (*vtypeJson, error) {

	doc := newVtypeJson()
	macMeta := new(unixMetadata)

	for _, f := range files {
		var machoFile *macho.File
		var err error

		if fatArch == "" {
			machoFile, err = macho.Open(f.FilePath)
			if err != nil {
				return nil, fmt.Errorf("could not open %s: %v", f.FilePath, err)
			}
			defer machoFile.Close()
		} else {
			fatFile, err := macho.OpenFat(f.FilePath)
			if err != nil {
				return nil, fmt.Errorf("could not open %s: %v", f.FilePath, err)
			}
			defer fatFile.Close()

			machoFile, err = findFatArch(fatFile, fatArch)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", f.FilePath, err)
			}
		}

		// process dwarf
		if extract := f.Extract & (DwarfTypes | DwarfSymbols); extract != 0 {
			var endian string

			if machoFile.ByteOrder == binary.LittleEndian {
				endian = "little"
			} else {
				endian = "big"
			}
			data, err := machoFile.DWARF()
			if err != nil {
				return nil, fmt.Errorf("could not get DWARF from %s: %v", f.FilePath, err)
			}

			if err = doc.addDwarf(data, endian, extract); err != nil {
				return nil, fmt.Errorf("error processing DWARF: %v", err)
			}

			// Add meta information
			fileMeta := newSourceMetadata(f.FilePath)
			fileMeta.Kind = "dwarf"
			if f.Extract&DwarfSymbols != 0 {
				macMeta.Symbols = append(macMeta.Symbols, fileMeta)
			}
			if f.Extract&DwarfTypes != 0 {
				macMeta.Types = append(macMeta.Types, fileMeta)
			}
		}

		// process symtab
		if extract := f.Extract & (SymTabSymbols | ConstantData); extract != 0 {
			if err := processMachoSymTab(doc, machoFile, extract); err != nil {
				return nil, fmt.Errorf("error processing symtab: %v", err)
			}

			// Add meta information
			fileMeta := newSourceMetadata(f.FilePath)
			fileMeta.Kind = "symtab"
			macMeta.Symbols = append(macMeta.Symbols, fileMeta)
		}
	}

	doc.Metadata.Mac = macMeta
	return doc, nil
}

func findFatArch(fatFile *macho.FatFile, arch string) (*macho.File, error) {
	var cpu macho.Cpu

	// Convert user provided arch string to macho.Cpu
	switch arch {
	case "i386":
		cpu = macho.Cpu386
	case "x86_64":
		cpu = macho.CpuAmd64
	default:
		return nil, fmt.Errorf("Unknown arch type %s. Supported types are i386 and x86_64", arch)
	}

	// Select the embedded dwarf file that matches the user architecture
	for _, a := range fatFile.Arches {
		if a.Cpu == cpu {
			return a.File, nil
		}
	}

	return nil, fmt.Errorf("does not contain requested architecture %s", arch)
}

// processMachoSymTab adds missing symbol information from SymTab to the vtypeJson doc
func processMachoSymTab(doc *vtypeJson, machoFile *macho.File, extract Extract) error {

	if doc == nil {
		return fmt.Errorf("invalid vtypeJSON: nil")
	}
	if machoFile == nil {
		return fmt.Errorf("invalid machoFile: nil")
	}

	voidType := make(map[string]interface{}, 0)
	voidType["kind"] = "base"
	voidType["name"] = "void"

	// Iterate over mach-O symbols in symtab. The symbols in symtab have an
	// address and name, but do not have type information. We can use this
	// symtab to fill in the missing addresses for symbols from DWARF.
	//
	// To compensate for the fact that the compiler adds a "_" prefix to symtab
	// symbols, we must check both the symbol name as it appears in symtab
	// (with "_") and also attempt to strip the leading "_" and check for that
	// symbol.
	symtab := machoFile.Symtab
	if symtab == nil {
		return fmt.Errorf("symtab command does not exist")
	}
	machoSyms := symtab.Syms
	if machoSyms == nil {
		return fmt.Errorf("symtab does not have any symbols")
	}

	// Determine how the names from symtab map to those of the DWARF with
	// respect to the presence or absence of the leading underscore
	exactMatchCount := 0
	strippedUnderscoreMatchCount := 0
	for _, machosym := range machoSyms {
		strippedName := strings.TrimPrefix(machosym.Name, "_")
		if _, ok := doc.Symbols[machosym.Name]; ok {
			exactMatchCount++
		}
		if _, ok := doc.Symbols[strippedName]; ok {
			strippedUnderscoreMatchCount++
		}
	}

	// If more stripped-underscore-symbols match, then the underscore
	// should be stripped from processing
	stripLeadingUnderscore := strippedUnderscoreMatchCount > exactMatchCount

	// we convert the constantDataSymbols slice to a map for fast lookups
	constantDataMap := make(map[string]bool)
	for _, constantSymbol := range constantMacosDataSymbols {
		constantDataMap[constantSymbol] = false
	}

	normalizeName := func(symName string) string {
		if stripLeadingUnderscore {
			symName = strings.TrimPrefix(symName, "_")
		}
		return symName
	}

	symbolsCb := func(machosym macho.Symbol) {
		symName := normalizeName(machosym.Name)
		sym, ok := doc.Symbols[symName]
		if !ok {
			sym = &vtypeSymbol{Address: machosym.Value, SymbolType: voidType}
		} else {
			sym.Address = machosym.Value
		}
		doc.Symbols[symName] = sym
	}

	constantDataCb := func(machosym macho.Symbol) {
		symName := normalizeName(machosym.Name)
		_, ok := constantDataMap[symName]
		if !ok {
			return
		}
		sym, ok := doc.Symbols[symName]
		if !ok {
			return
		}
		dataLen, ok := sym.SymbolType["count"].(int64)
		if !ok {
			return
		}
		data, err := readMachoSymbol(machoFile, machosym, uint64(dataLen))
		if err != nil {
			return
		}
		sym.ConstantData = data
		doc.Symbols[symName] = sym
	}

	callBacks := []func(machosym macho.Symbol){}

	if extract&SymTabSymbols != 0 {
		callBacks = append(callBacks, symbolsCb)
	}
	if extract&ConstantData != 0 {
		callBacks = append(callBacks, constantDataCb)
	}

	for _, machosym := range machoSyms {
		for _, cb := range callBacks {
			cb(machosym)
		}
	}

	return nil
}

func generateLinux(files FilesToProcess) (*vtypeJson, error) {

	doc := newVtypeJson()
	linuxMeta := new(unixMetadata)

	for _, f := range files {
		var elfFile *elf.File
		var err error

		// process system map text, and skip to next file
		if extract := f.Extract & (SystemMap); extract != 0 {
			r, err := os.Open(f.FilePath)
			if err != nil {
				return nil, fmt.Errorf("could not open %s: %v", f.FilePath, err)
			}

			if err := processSystemMap(doc, r); err != nil {
				return nil, fmt.Errorf("error processing system map: %v", err)
			}

			// Add meta information
			fileMeta := newSourceMetadata(f.FilePath)
			fileMeta.Kind = "system-map"
			linuxMeta.Symbols = append(linuxMeta.Symbols, fileMeta)

			continue
		}

		// process binary elf files
		elfFile, err = elf.Open(f.FilePath)
		if err != nil {
			return nil, fmt.Errorf("could not open %s: %v", f.FilePath, err)
		}
		defer elfFile.Close()

		// process dwarf
		if extract := f.Extract & (DwarfTypes | DwarfSymbols); extract != 0 {
			var endian string

			if elfFile.ByteOrder == binary.LittleEndian {
				endian = "little"
			} else {
				endian = "big"
			}

			data, err := elfFile.DWARF()
			if err != nil {
				return nil, fmt.Errorf("could not get DWARF from %s: %v", f.FilePath, err)
			}

			if err = doc.addDwarf(data, endian, extract); err != nil {
				return nil, fmt.Errorf("error processing DWARF: %v", err)
			}

			// Add meta information
			fileMeta := newSourceMetadata(f.FilePath)
			fileMeta.Kind = "dwarf"
			if f.Extract&DwarfSymbols != 0 {
				linuxMeta.Symbols = append(linuxMeta.Symbols, fileMeta)
			}
			if f.Extract&DwarfTypes != 0 {
				linuxMeta.Types = append(linuxMeta.Types, fileMeta)
			}
		}

		// process symtab
		if extract := f.Extract & (SymTabSymbols | ConstantData); extract != 0 {
			if err := processElfSymTab(doc, elfFile, extract); err != nil {
				return nil, fmt.Errorf("error processing symtab: %v", err)
			}

			// Add meta information
			fileMeta := newSourceMetadata(f.FilePath)
			fileMeta.Kind = "symtab"
			linuxMeta.Symbols = append(linuxMeta.Symbols, fileMeta)
		}

	}
	doc.Metadata.Linux = linuxMeta
	return doc, nil
}

// processSystemMap adds the missing symbol information from system.map to vtypeJson doc
func processSystemMap(doc *vtypeJson, systemMap io.Reader) error {

	voidType := make(map[string]interface{}, 0)
	voidType["kind"] = "base"
	voidType["name"] = "void"

	scanner := bufio.NewScanner(systemMap)

	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Fields(line)
		addr, err := strconv.ParseUint(words[0], 16, 64)
		if err != nil {
			return fmt.Errorf("failed parsing %s", line)
		}
		symName := words[2]

		sym, ok := doc.Symbols[symName]
		if !ok {
			sym = &vtypeSymbol{Address: addr, SymbolType: voidType}
		} else {
			sym.Address = addr
		}
		doc.Symbols[symName] = sym
	}
	return nil
}

// processElfSymTab adds missing symbol information from SymTab to the vtypeJson doc
func processElfSymTab(doc *vtypeJson, elfFile *elf.File, extract Extract) error {
	if doc == nil {
		return fmt.Errorf("invalid vtypeJSON: nil")
	}
	if elfFile == nil {
		return fmt.Errorf("invalid elfFile: nil")
	}

	// we convert the constantDataSymbols slice to a map for fast lookups
	constantDataMap := make(map[string]bool)
	for _, constantSymbol := range constantLinuxDataSymbols {
		constantDataMap[constantSymbol] = false
	}

	// go through the ELF symbols looking for missing addresses
	elfsymbols, err := elfFile.Symbols()
	if err != nil {
		return fmt.Errorf("could not get symbols: %v", err)
	}

	voidType := make(map[string]interface{}, 0)
	voidType["kind"] = "base"
	voidType["name"] = "void"

	symbolsCb := func(elfsym elf.Symbol) {
		sym, ok := doc.Symbols[elfsym.Name]
		if !ok {
			sym = &vtypeSymbol{Address: elfsym.Value, SymbolType: voidType}
		} else {
			sym.Address = elfsym.Value
		}
		doc.Symbols[elfsym.Name] = sym
	}

	constantDataCb := func(elfsym elf.Symbol) {
		_, ok := constantDataMap[elfsym.Name]
		if !ok {
			return
		}
		sym, ok := doc.Symbols[elfsym.Name]
		if !ok {
			return
		}
		data, _ := readELFSymbol(elfFile, elfsym)
		sym.ConstantData = data
		doc.Symbols[elfsym.Name] = sym
	}

	callBacks := []func(elfsym elf.Symbol){}

	if extract&SymTabSymbols != 0 {
		callBacks = append(callBacks, symbolsCb)
	}
	if extract&ConstantData != 0 {
		callBacks = append(callBacks, constantDataCb)
	}

	for _, elfsym := range elfsymbols {

		for _, cb := range callBacks {
			cb(elfsym)
		}
	}
	return nil
}
