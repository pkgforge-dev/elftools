package main

import (

	"debug/elf"

	"encoding/binary"

	"fmt"

	"os"

	"path/filepath"

	"strings"

	"github.com/spf13/cobra"

)

type SecurityFeatures struct {

	ASLR         bool

	PIE          bool

	NXBit        bool

	StackCanary  bool

	RELRO        string // "None", "Partial", "Full", "N/A"

	Stripped     bool

	Fortify      bool

	Runpath      bool

	Rpath        bool

	Static       bool

	StaticPIE    bool

}

var (

	jsonOutput   bool

	verboseMode  bool

	showScore    bool

	showRecommendations bool

)

func main() {

	rootCmd := &cobra.Command{

		Use:   "elfsec <binary>",

		Short: "ELF Security Hardening Checker",

		Long: `A comprehensive security analysis tool for ELF binaries.

Checks for various security hardening features including ASLR, PIE, NX bit,

stack canaries, RELRO, and more. Supports both static and dynamic binaries.`,

		Version: "1.0.0",

		Args:    cobra.ExactArgs(1),

		RunE:    runAnalysis,

	}

	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")

	rootCmd.Flags().BoolVarP(&verboseMode, "verbose", "v", false, "Enable verbose output")

	rootCmd.Flags().BoolVarP(&showScore, "score", "s", true, "Show security score")

	rootCmd.Flags().BoolVarP(&showRecommendations, "recommendations", "r", true, "Show security recommendations")

	if err := rootCmd.Execute(); err != nil {

		os.Exit(1)

	}

}

func runAnalysis(cmd *cobra.Command, args []string) error {

	filename := args[0]

	

	// Check if file exists

	if _, err := os.Stat(filename); os.IsNotExist(err) {

		return fmt.Errorf("file '%s' does not exist", filename)

	}

	// Analyze the binary

	features, err := analyzeELF(filename)

	if err != nil {

		return fmt.Errorf("failed to analyze '%s': %v", filename, err)

	}

	// Output results

	if jsonOutput {

		printJSONResults(filename, features)

	} else {

		printResults(filename, features)

	}

	return nil

}

func analyzeELF(filename string) (*SecurityFeatures, error) {

	file, err := elf.Open(filename)

	if err != nil {

		return nil, fmt.Errorf("failed to open ELF file: %v", err)

	}

	defer file.Close()

	features := &SecurityFeatures{

		RELRO: "None",

	}

	// Determine if binary is static

	features.Static = isStaticBinary(file)

	

	// Check PIE (Position Independent Executable)

	features.PIE = file.Type == elf.ET_DYN

	

	// Check for static-PIE (ET_DYN with no dynamic section)

	if features.PIE && features.Static {

		features.StaticPIE = true

	}

	// Check ASLR - PIE enables ASLR for executables

	features.ASLR = features.PIE

	// Check NX bit (No Execute) - look for GNU_STACK segment

	features.NXBit = checkNXBit(file)

	// Check for stack canary

	features.StackCanary = checkStackCanary(file)

	// Check RELRO (only for dynamic binaries)

	if !features.Static {

		features.RELRO = checkRELRO(file)

	} else {

		features.RELRO = "N/A"

	}

	// Check if binary is stripped

	features.Stripped = checkStripped(file)

	// Check for FORTIFY_SOURCE

	features.Fortify = checkFortify(file)

	// Check for RUNPATH/RPATH (only for dynamic binaries)

	if !features.Static {

		features.Runpath, features.Rpath = checkRunpathRpath(file)

	}

	return features, nil

}

func isStaticBinary(file *elf.File) bool {

	// Check for PT_INTERP segment (dynamic linker)

	for _, prog := range file.Progs {

		if prog.Type == elf.PT_INTERP {

			return false

		}

	}

	

	// Check for .dynamic section

	if file.Section(".dynamic") != nil {

		return false

	}

	

	// Check for dynamic symbols

	if _, err := file.DynamicSymbols(); err == nil {

		return false

	}

	

	return true

}

func checkNXBit(file *elf.File) bool {

	for _, prog := range file.Progs {

		if prog.Type == elf.PT_GNU_STACK {

			// If GNU_STACK segment exists and is not executable, NX is enabled

			return (prog.Flags & elf.PF_X) == 0

		}

	}

	// If no GNU_STACK segment, assume NX is enabled (default behavior)

	return true

}

func checkStackCanary(file *elf.File) bool {

	// Look for stack canary symbols

	symbols, err := file.Symbols()

	if err != nil {

		// Try dynamic symbols if regular symbols fail

		symbols, err = file.DynamicSymbols()

		if err != nil {

			return false

		}

	}

	canarySymbols := []string{

		"__stack_chk_fail",

		"__stack_chk_guard",

		"__intel_security_cookie",

	}

	for _, symbol := range symbols {

		for _, canary := range canarySymbols {

			if strings.Contains(symbol.Name, canary) {

				return true

			}

		}

	}

	return false

}

func checkRELRO(file *elf.File) string {

	hasGNURelro := false

	hasBindNow := false

	// Check for GNU_RELRO segment

	for _, prog := range file.Progs {

		if prog.Type == elf.PT_GNU_RELRO {

			hasGNURelro = true

			break

		}

	}

	// Check for BIND_NOW flag in dynamic section

	if dynSection := file.Section(".dynamic"); dynSection != nil {

		data, err := dynSection.Data()

		if err == nil {

			// Parse dynamic section entries

			if file.Class == elf.ELFCLASS64 {

				hasBindNow = parseDynamic64(data, file.Data)

			} else {

				hasBindNow = parseDynamic32(data, file.Data)

			}

		}

	}

	if hasGNURelro && hasBindNow {

		return "Full"

	} else if hasGNURelro {

		return "Partial"

	}

	return "None"

}

func parseDynamic64(data []byte, order elf.Data) bool {

	var byteOrder binary.ByteOrder

	if order == elf.ELFDATA2LSB {

		byteOrder = binary.LittleEndian

	} else {

		byteOrder = binary.BigEndian

	}

	for i := 0; i < len(data)-15; i += 16 {

		tag := byteOrder.Uint64(data[i : i+8])

		

		if tag == 0x18 { // DT_BIND_NOW

			return true

		}

		if tag == 0x1e { // DT_FLAGS

			val := byteOrder.Uint64(data[i+8 : i+16])

			if val&0x8 != 0 { // DF_BIND_NOW

				return true

			}

		}

	}

	return false

}

func parseDynamic32(data []byte, order elf.Data) bool {

	var byteOrder binary.ByteOrder

	if order == elf.ELFDATA2LSB {

		byteOrder = binary.LittleEndian

	} else {

		byteOrder = binary.BigEndian

	}

	for i := 0; i < len(data)-7; i += 8 {

		tag := byteOrder.Uint32(data[i : i+4])

		

		if tag == 0x18 { // DT_BIND_NOW

			return true

		}

		if tag == 0x1e { // DT_FLAGS

			val := byteOrder.Uint32(data[i+4 : i+8])

			if val&0x8 != 0 { // DF_BIND_NOW

				return true

			}

		}

	}

	return false

}

func checkStripped(file *elf.File) bool {

	// Check if symbol table sections exist

	for _, section := range file.Sections {

		if section.Type == elf.SHT_SYMTAB {

			return false

		}

	}

	return true

}

func checkFortify(file *elf.File) bool {

	// Look for fortified function symbols

	symbols, err := file.Symbols()

	if err != nil {

		symbols, err = file.DynamicSymbols()

		if err != nil {

			return false

		}

	}

	fortifySymbols := []string{

		"__memcpy_chk",

		"__memmove_chk",

		"__memset_chk",

		"__strcpy_chk",

		"__strcat_chk",

		"__sprintf_chk",

		"__snprintf_chk",

		"__printf_chk",

		"__fprintf_chk",

		"__vprintf_chk",

		"__vfprintf_chk",

		"__vsprintf_chk",

		"__vsnprintf_chk",

	}

	for _, symbol := range symbols {

		for _, fortify := range fortifySymbols {

			if strings.Contains(symbol.Name, fortify) {

				return true

			}

		}

	}

	return false

}

func checkRunpathRpath(file *elf.File) (bool, bool) {

	hasRunpath := false

	hasRpath := false

	if dynSection := file.Section(".dynamic"); dynSection != nil {

		data, err := dynSection.Data()

		if err == nil {

			if file.Class == elf.ELFCLASS64 {

				hasRunpath, hasRpath = parseDynamicPaths64(data, file.Data)

			} else {

				hasRunpath, hasRpath = parseDynamicPaths32(data, file.Data)

			}

		}

	}

	return hasRunpath, hasRpath

}

func parseDynamicPaths64(data []byte, order elf.Data) (bool, bool) {

	var byteOrder binary.ByteOrder

	if order == elf.ELFDATA2LSB {

		byteOrder = binary.LittleEndian

	} else {

		byteOrder = binary.BigEndian

	}

	hasRunpath := false

	hasRpath := false

	for i := 0; i < len(data)-15; i += 16 {

		tag := byteOrder.Uint64(data[i : i+8])

		

		if tag == 0x1d { // DT_RUNPATH

			hasRunpath = true

		}

		if tag == 0x0f { // DT_RPATH

			hasRpath = true

		}

	}

	return hasRunpath, hasRpath

}

func parseDynamicPaths32(data []byte, order elf.Data) (bool, bool) {

	var byteOrder binary.ByteOrder

	if order == elf.ELFDATA2LSB {

		byteOrder = binary.LittleEndian

	} else {

		byteOrder = binary.BigEndian

	}

	hasRunpath := false

	hasRpath := false

	for i := 0; i < len(data)-7; i += 8 {

		tag := byteOrder.Uint32(data[i : i+4])

		

		if tag == 0x1d { // DT_RUNPATH

			hasRunpath = true

		}

		if tag == 0x0f { // DT_RPATH

			hasRpath = true

		}

	}

	return hasRunpath, hasRpath

}

func printJSONResults(filename string, features *SecurityFeatures) {

	fmt.Printf(`{

  "file": "%s",

  "binary_type": "%s",

  "security_features": {

    "aslr": %t,

    "pie": %t,

    "nx_bit": %t,

    "stack_canary": %t,

    "relro": "%s",

    "stripped": %t,

    "fortify_source": %t,

    "runpath": %t,

    "rpath": %t

  },

  "security_score": {

    "score": %d,

    "total": %d,

    "percentage": %.1f

  }

}`,

		filepath.Base(filename),

		getBinaryType(features),

		features.ASLR,

		features.PIE,

		features.NXBit,

		features.StackCanary,

		features.RELRO,

		features.Stripped,

		features.Fortify,

		features.Runpath,

		features.Rpath,

		calculateScore(features),

		getTotalScore(features),

		calculatePercentage(features),

	)

}

func printResults(filename string, features *SecurityFeatures) {

	fmt.Printf("ELF Security Analysis for: %s\n", filepath.Base(filename))

	fmt.Printf("=" + strings.Repeat("=", len(filename)+25) + "\n\n")

	// Binary type information

	fmt.Printf("Binary Type: %s\n", getBinaryType(features))

	if verboseMode {

		fmt.Printf("Static Binary: %t\n", features.Static)

		fmt.Printf("Static PIE: %t\n", features.StaticPIE)

	}

	fmt.Println()

	// Security features

	fmt.Println("Security Features:")

	fmt.Println("------------------")

	

	// Helper function to print status

	printStatus := func(name string, enabled bool, info string) {

		var status string

		if enabled {

			status = "✓ ENABLED"

		} else {

			status = "✗ DISABLED"

		}

		fmt.Printf("%-20s: %s", name, status)

		if info != "" {

			fmt.Printf(" (%s)", info)

		}

		fmt.Println()

	}

	printStatus("ASLR", features.ASLR, "")

	printStatus("PIE", features.PIE, "")

	printStatus("NX Bit", features.NXBit, "")

	printStatus("Stack Canary", features.StackCanary, "")

	

	if features.RELRO != "N/A" {

		relroEnabled := features.RELRO != "None"

		printStatus("RELRO", relroEnabled, features.RELRO)

	} else {

		fmt.Printf("%-20s: %s\n", "RELRO", "N/A (Static Binary)")

	}

	

	printStatus("Stripped", features.Stripped, "")

	printStatus("FORTIFY_SOURCE", features.Fortify, "")

	

	if !features.Static {

		printStatus("RUNPATH", features.Runpath, "")

		printStatus("RPATH", features.Rpath, "")

	} else {

		fmt.Printf("%-20s: %s\n", "RUNPATH", "N/A (Static Binary)")

		fmt.Printf("%-20s: %s\n", "RPATH", "N/A (Static Binary)")

	}

	// Security score

	if showScore {

		score := calculateScore(features)

		total := getTotalScore(features)

		percentage := calculatePercentage(features)

		

		fmt.Printf("\nSecurity Score: %d/%d (%.1f%%)\n", score, total, percentage)

		

		if verboseMode {

			printScoreBreakdown(features)

		}

	}

	// Recommendations

	if showRecommendations {

		printRecommendations(features)

	}

}

func getBinaryType(features *SecurityFeatures) string {

	if features.StaticPIE {

		return "Static PIE"

	} else if features.Static {

		return "Static"

	} else if features.PIE {

		return "Dynamic PIE"

	} else {

		return "Dynamic"

	}

}

func calculateScore(features *SecurityFeatures) int {

	score := 0

	

	if features.ASLR { score++ }

	if features.PIE { score++ }

	if features.NXBit { score++ }

	if features.StackCanary { score++ }

	

	// RELRO scoring

	if features.RELRO == "Full" {

		score += 2

	} else if features.RELRO == "Partial" {

		score += 1

	}

	

	if features.Stripped { score++ }

	if features.Fortify { score++ }

	

	// For static binaries, not having RUNPATH/RPATH is not applicable

	if !features.Static && !features.Runpath && !features.Rpath {

		score++

	}

	

	return score

}

func getTotalScore(features *SecurityFeatures) int {

	if features.Static {

		return 8 // ASLR, PIE, NX, Stack Canary, RELRO(2), Stripped, Fortify

	}

	return 9 // Add RUNPATH/RPATH for dynamic binaries

}

func calculatePercentage(features *SecurityFeatures) float64 {

	score := calculateScore(features)

	total := getTotalScore(features)

	return float64(score) / float64(total) * 100

}

func printScoreBreakdown(features *SecurityFeatures) {

	fmt.Println("\nScore Breakdown:")

	fmt.Println("----------------")

	fmt.Printf("ASLR:           %s\n", getScoreSymbol(features.ASLR))

	fmt.Printf("PIE:            %s\n", getScoreSymbol(features.PIE))

	fmt.Printf("NX Bit:         %s\n", getScoreSymbol(features.NXBit))

	fmt.Printf("Stack Canary:   %s\n", getScoreSymbol(features.StackCanary))

	

	if features.RELRO != "N/A" {

		relroScore := ""

		switch features.RELRO {

		case "Full":

			relroScore = "✓✓ (2 points)"

		case "Partial":

			relroScore = "✓✗ (1 point)"

		default:

			relroScore = "✗✗ (0 points)"

		}

		fmt.Printf("RELRO:          %s\n", relroScore)

	}

	

	fmt.Printf("Stripped:       %s\n", getScoreSymbol(features.Stripped))

	fmt.Printf("FORTIFY_SOURCE: %s\n", getScoreSymbol(features.Fortify))

	

	if !features.Static {

		fmt.Printf("No RUNPATH/RPATH: %s\n", getScoreSymbol(!features.Runpath && !features.Rpath))

	}

}

func getScoreSymbol(enabled bool) string {

	if enabled {

		return "✓ (1 point)"

	}

	return "✗ (0 points)"

}

func printRecommendations(features *SecurityFeatures) {

	recommendations := []string{}

	

	if !features.PIE {

		recommendations = append(recommendations, "Enable PIE: compile with -fPIE -pie")

	}

	if !features.StackCanary {

		recommendations = append(recommendations, "Enable stack canary: compile with -fstack-protector-strong")

	}

	if features.RELRO != "Full" && features.RELRO != "N/A" {

		recommendations = append(recommendations, "Enable full RELRO: link with -Wl,-z,relro,-z,now")

	}

	if !features.Fortify {

		recommendations = append(recommendations, "Enable FORTIFY_SOURCE: compile with -D_FORTIFY_SOURCE=2")

	}

	if !features.Static && (features.Runpath || features.Rpath) {

		recommendations = append(recommendations, "Remove insecure RUNPATH/RPATH entries")

	}

	

	if len(recommendations) > 0 {

		fmt.Printf("\nRecommendations:\n")

		fmt.Printf("----------------\n")

		for _, rec := range recommendations {

			fmt.Printf("• %s\n", rec)

		}

	} else {

		fmt.Printf("\n✓ All security features are properly configured!\n")

	}

}