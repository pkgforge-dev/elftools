package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type SecurityFeatures struct {
	ASLRSupport   bool   // Binary supports ASLR (PIE-compiled)
	ASLREnabled   bool   // Kernel ASLR is enabled
	ASLRLevel     int    // ASLR level (0, 1, 2)
	PIE           bool
	NXBit         bool
	StackCanary   bool
	RELRO         string // "None", "Partial", "Full", "N/A"
	Stripped      bool
	Fortify       bool
	Runpath       bool
	Rpath         bool
	Static        bool
	StaticPIE     bool
}

var (
	jsonOutput          bool
	verboseMode         bool
	showScore           bool
	showRecommendations bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "elfsec <binary>",
		Short: "ELF Security Hardening Checker",
		Long: `Check for various security hardening features including ASLR support, PIE, NX bit,
stack canaries, RELRO, and more.`,
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

	// Validate it's actually an ELF file
	if file.Class != elf.ELFCLASS32 && file.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("invalid ELF class")
	}

	features := &SecurityFeatures{
		RELRO: "None",
	}

	// Determine if binary is static - check this first
	features.Static = isStaticBinary(file)

	// Check PIE (Position Independent Executable)
	features.PIE = isPIEExecutable(file)

	// For static binaries, PIE detection is more complex
	if features.Static && features.PIE {
		features.StaticPIE = true
	}

	// Check ASLR support - depends on PIE and binary type
	if features.Static {
		// For static binaries, ASLR is only supported with static-PIE
		features.ASLRSupport = features.StaticPIE
	} else {
		// For dynamic binaries, PIE enables ASLR support
		features.ASLRSupport = features.PIE
	}

	// Check kernel ASLR status
	features.ASLREnabled, features.ASLRLevel = checkKernelASLR()

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

func checkKernelASLR() (bool, int) {
	// Try to read /proc/sys/kernel/randomize_va_space
	data, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err != nil {
		// If we can't read the file, we can't determine ASLR status
		return false, -1
	}

	level := strings.TrimSpace(string(data))
	switch level {
	case "0":
		return false, 0
	case "1":
		return true, 1
	case "2":
		return true, 2
	default:
		return false, -1
	}
}

func isPIEExecutable(file *elf.File) bool {
	// PIE executables are ET_DYN with entry point or PT_INTERP
	if file.Type != elf.ET_DYN {
		return false
	}

	// Check for program interpreter (dynamic executables)
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_INTERP {
			return true
		}
	}

	// Check for entry point (static-PIE)
	if file.Entry != 0 {
		return true
	}

	return false
}

func isStaticBinary(file *elf.File) bool {
	// Method 1: Check for PT_INTERP segment (program interpreter)
	// If present, it's definitely dynamic - equivalent to readelf -p '.interp'
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_INTERP {
			return false
		}
	}

	// Method 2: Check for NEEDED entries in dynamic section
	// This is equivalent to readelf --dynamic | grep NEEDED
	// Most reliable method - if there are NEEDED entries, it's dynamic
	if dynSection := file.Section(".dynamic"); dynSection != nil {
		data, err := dynSection.Data()
		if err == nil {
			var hasNeeded bool
			if file.Class == elf.ELFCLASS64 {
				hasNeeded = checkNeeded64(data, file.Data)
			} else {
				hasNeeded = checkNeeded32(data, file.Data)
			}
			// If we found NEEDED entries, it's dynamic
			if hasNeeded {
				return false
			}
		}
	}

	// If we have no PT_INTERP and no NEEDED entries, it's static
	// This correctly handles both ET_EXEC (traditional static) and ET_DYN (static-PIE)
	return true
}

func checkNXBit(file *elf.File) bool {
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			// If GNU_STACK segment exists and is not executable, NX is enabled
			return (prog.Flags & elf.PF_X) == 0
		}
	}
	// If no GNU_STACK segment, check system default behavior
	// Modern systems default to NX enabled, but we can't be 100% certain
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

func checkNeeded64(data []byte, order elf.Data) bool {
	if len(data) < 16 {
		return false
	}

	var byteOrder binary.ByteOrder
	if order == elf.ELFDATA2LSB {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	for i := 0; i < len(data)-15; i += 16 {
		tag := byteOrder.Uint64(data[i : i+8])

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

		// DT_NEEDED = 1 - indicates dependency on shared library
		if tag == 1 {
			return true
		}
	}
	return false
}

func checkNeeded32(data []byte, order elf.Data) bool {
	if len(data) < 8 {
		return false
	}

	var byteOrder binary.ByteOrder
	if order == elf.ELFDATA2LSB {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	for i := 0; i < len(data)-7; i += 8 {
		tag := byteOrder.Uint32(data[i : i+4])

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

		// DT_NEEDED = 1 - indicates dependency on shared library
		if tag == 1 {
			return true
		}
	}
	return false
}

func parseDynamic64(data []byte, order elf.Data) bool {
	if len(data) < 16 {
		return false
	}

	var byteOrder binary.ByteOrder
	if order == elf.ELFDATA2LSB {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	for i := 0; i < len(data)-15; i += 16 {
		tag := byteOrder.Uint64(data[i : i+8])

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

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
	if len(data) < 8 {
		return false
	}

	var byteOrder binary.ByteOrder
	if order == elf.ELFDATA2LSB {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	for i := 0; i < len(data)-7; i += 8 {
		tag := byteOrder.Uint32(data[i : i+4])

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

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
	if len(data) < 16 {
		return false, false
	}

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

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

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
	if len(data) < 8 {
		return false, false
	}

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

		// Check for DT_NULL (end of dynamic section)
		if tag == 0 {
			break
		}

		if tag == 0x1d { // DT_RUNPATH
			hasRunpath = true
		}
		if tag == 0x0f { // DT_RPATH
			hasRpath = true
		}
	}

	return hasRunpath, hasRpath
}

type JSONOutput struct {
	File           string `json:"file"`
	BinaryType     string `json:"binary_type"`
	SecurityFeatures struct {
		ASLRSupport   bool   `json:"aslr_support"`
		ASLREnabled   bool   `json:"aslr_enabled"`
		ASLRLevel     int    `json:"aslr_level"`
		PIE           bool   `json:"pie"`
		NXBit         bool   `json:"nx_bit"`
		StackCanary   bool   `json:"stack_canary"`
		RELRO         string `json:"relro"`
		Stripped      bool   `json:"stripped"`
		FortifySource bool   `json:"fortify_source"`
		Runpath       bool   `json:"runpath"`
		Rpath         bool   `json:"rpath"`
	} `json:"security_features"`
	SecurityScore struct {
		Score      int     `json:"score"`
		Total      int     `json:"total"`
		Percentage string `json:"percentage"`
	} `json:"security_score"`
}

func printJSONResults(filename string, features *SecurityFeatures) {
	out := JSONOutput{
		File:       filepath.Base(filename),
		BinaryType: getBinaryType(features),
	}
	out.SecurityFeatures.ASLRSupport = features.ASLRSupport
	out.SecurityFeatures.ASLREnabled = features.ASLREnabled
	out.SecurityFeatures.ASLRLevel = features.ASLRLevel
	out.SecurityFeatures.PIE = features.PIE
	out.SecurityFeatures.NXBit = features.NXBit
	out.SecurityFeatures.StackCanary = features.StackCanary
	out.SecurityFeatures.RELRO = strings.ToLower(features.RELRO)
	out.SecurityFeatures.Stripped = features.Stripped
	out.SecurityFeatures.FortifySource = features.Fortify
	out.SecurityFeatures.Runpath = features.Runpath
	out.SecurityFeatures.Rpath = features.Rpath

	score := calculateScore(features)
	total := getTotalScore(features)
	percentage := (float64(score) / float64(total)) * 100.0

	out.SecurityScore.Score = score
	out.SecurityScore.Total = total
	out.SecurityScore.Percentage = fmt.Sprintf("%.2f%%", percentage)

	jsonBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Printf("error marshaling JSON: %v\n", err)
		return
	}

	fmt.Println(string(jsonBytes))
}

func printResults(filename string, features *SecurityFeatures) {
	fmt.Printf("🔍 ELF Security Analysis for: %s\n", filepath.Base(filename))
	fmt.Println("=================================\n")

	// Binary info
	fmt.Printf("📦 Binary Type        : %s\n", getBinaryType(features))
	fmt.Println()

	// Security Features
	fmt.Println("🛡️  Security Features")
	fmt.Println("----------------------\n")

	// Formatter
	printStatus := func(name string, enabled bool, info string, description string) {
		var status string
		if enabled {
			status = "✓ SUPPORTED"
		} else {
			status = "✗ NOT SUPPORTED"
		}
		if info != "" {
			status = fmt.Sprintf("%-17s (%s)", status, info)
		} else {
			status = fmt.Sprintf("%-17s", status)
		}
		if description != "" {
			fmt.Printf("   %-20s : %-20s - %s\n", name, status, description)
		} else {
			fmt.Printf("   %-20s : %-20s\n", name, status)
		}
	}

	// ASLR Section
	fmt.Println("🔐 ASLR (Address Space Layout Randomization)")
	fmt.Println("   -----------------------------------------")

	printStatus("Binary Support", features.ASLRSupport, "", "binary is compiled to support ASLR")

	if features.ASLRLevel >= 0 {
		var kernelStatus string
		switch features.ASLRLevel {
		case 0:
			kernelStatus = "Disabled"
		case 1:
			kernelStatus = "Conservative"
		case 2:
			kernelStatus = "Full"
		}
		kernelState := map[bool]string{true: "✓ ENABLED", false: "✗ DISABLED"}[features.ASLREnabled]
		fmt.Printf("   %-20s : %-20s (%s)\n", "Kernel ASLR", kernelState, kernelStatus)
	} else {
		fmt.Printf("   %-20s : %-20s\n", "Kernel ASLR", "? UNKNOWN - cannot read kernel randomize_va_space")
	}

	effectiveASLR := features.ASLRSupport && features.ASLREnabled
	fmt.Printf("   %-20s : %s\n", "Effective ASLR", map[bool]string{true: "✓ ACTIVE", false: "✗ INACTIVE"}[effectiveASLR])
	fmt.Println()

	// Other Flags
	fmt.Println("🚧 Other Security Flags")
	fmt.Println("   ---------------------")
	printStatus("PIE", features.PIE, "", "position independent executable - enables full ASLR")
	printStatus("NX Bit", features.NXBit, "", "prevents execution of non-executable memory pages")
	printStatus("Stack Canary", features.StackCanary, "", "detects stack buffer overflows")

	if features.RELRO != "N/A" {
		printStatus("RELRO", features.RELRO != "None", features.RELRO, "makes GOT read-only after relocation")
	} else {
		fmt.Printf("   %-20s : %-20s - %s\n", "RELRO", "N/A", "Static Binary")
	}

	printStatus("Stripped", features.Stripped, "", "removes symbol table, harder to reverse-engineer")
	printStatus("FORTIFY_SOURCE", features.Fortify, "", "detects some buffer overflows in libc functions")

	if !features.Static {
		printStatus("RUNPATH", features.Runpath, "", "may affect runtime library search path")
		printStatus("RPATH", features.Rpath, "", "deprecated, insecure search path for libraries")
	} else {
		fmt.Printf("   %-20s : %-20s - %s\n", "RUNPATH", "N/A", "Static Binary")
		fmt.Printf("   %-20s : %-20s - %s\n", "RPATH", "N/A", "Static Binary")
	}

	// Score
	if showScore {
		score := calculateScore(features)
		total := getTotalScore(features)
		percentage := calculatePercentage(features)

		fmt.Println()
		fmt.Printf("📊 Security Score       : %d/%d (%.1f%%)\n", score, total, percentage)

		if verboseMode {
			printScoreBreakdown(features)
		}
	}

	// Recommendations
	if showRecommendations {
		fmt.Println()
		printRecommendations(features)
	}
}

func getBinaryType(features *SecurityFeatures) string {
	if features.StaticPIE {
		return "static-pie"
	} else if features.Static {
		return "static"
	} else if features.PIE {
		return "dynamic-pie"
	} else {
		return "dynamic"
	}
}

func calculateScore(features *SecurityFeatures) int {
	score := 0

	// Score based on effective ASLR (both support and kernel enabled)
	if features.ASLRSupport && features.ASLREnabled {
		score++
	}

	if features.PIE {
		score++
	}
	if features.NXBit {
		score++
	}
	if features.StackCanary {
		score++
	}

	// RELRO scoring
	switch strings.ToLower(features.RELRO) {
	case "full":
		score += 2
	case "partial":
		score += 1
	case "n/a":
		// For static binaries, RELRO is N/A, so we give full points
		score += 2
	}

	if features.Stripped {
		score++
	}
	if features.Fortify {
		score++
	}

	// For dynamic binaries, not having RUNPATH/RPATH is good
	// For static binaries, these are N/A, so we give the point
	if features.Static {
		score++ // N/A for static binaries = full points
	} else if !features.Runpath && !features.Rpath {
		score++
	}

	return score
}

func getTotalScore(features *SecurityFeatures) int {
	// Total is always 9 regardless of binary type
	// ASLR(1) + PIE(1) + NX(1) + Stack Canary(1) + RELRO(2) + Stripped(1) + Fortify(1) + No RUNPATH/RPATH(1) = 9
	return 9
}

func calculatePercentage(features *SecurityFeatures) float64 {
	score := calculateScore(features)
	total := getTotalScore(features)
	return float64(score) / float64(total) * 100
}

func printScoreBreakdown(features *SecurityFeatures) {
	fmt.Println("\nScore Breakdown:")
	fmt.Println("----------------")
	effectiveASLR := features.ASLRSupport && features.ASLREnabled
	fmt.Printf("ASLR:           %s\n", getScoreSymbol(effectiveASLR))
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
	} else {
		fmt.Printf("RELRO:          N/A (2 points - not applicable)\n")
	}

	fmt.Printf("Stripped:       %s\n", getScoreSymbol(features.Stripped))
	fmt.Printf("FORTIFY_SOURCE: %s\n", getScoreSymbol(features.Fortify))

	if !features.Static {
		fmt.Printf("No RUNPATH/RPATH: %s\n", getScoreSymbol(!features.Runpath && !features.Rpath))
	} else {
		fmt.Printf("No RUNPATH/RPATH: N/A (1 point - not applicable)\n")
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

	if !features.ASLRSupport {
		if !features.PIE {
			recommendations = append(recommendations, "Enable ASLR support: compile with -fPIE -pie")
		}
	} else if !features.ASLREnabled && features.ASLRLevel >= 0 {
		recommendations = append(recommendations, "Enable kernel ASLR: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space")
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
		fmt.Printf("\n💡 Recommendations:\n")
		fmt.Printf("-------------------\n")
		for _, rec := range recommendations {
			fmt.Printf("• %s\n", rec)
		}
	} else {
		fmt.Printf("\n✓ All security features are properly configured!\n")
	}
}