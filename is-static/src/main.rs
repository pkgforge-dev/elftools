use goblin::elf::Elf;
use std::env;
use std::fs;
use std::process;

#[derive(Debug)]
struct StaticAnalysisResult {
    is_static: bool,
    evidence: Vec<String>,
    confidence: f32,
    primary_indicators: Vec<String>,
    secondary_indicators: Vec<String>,
    file_size: u64,
    stripped: bool,
    bitness: u8, // 32 or 64
    architecture: String,
}

fn analyze_elf_static_linking(file_path: &str) -> Result<StaticAnalysisResult, Box<dyn std::error::Error>> {
    let buffer = fs::read(file_path)?;
    let file_size = buffer.len() as u64;
    let elf = Elf::parse(&buffer)?;
    
    let mut evidence = Vec::new();
    let mut primary_indicators = Vec::new();
    let mut secondary_indicators = Vec::new();
    
    // Primary indicators (definitive)
    let mut has_pt_interp = false;
    let mut has_pt_dynamic = false;
    let mut has_dynamic_section = false;
    let mut has_dynamic_symbols = false;
    let mut has_needed_entries = false;
    
    // Secondary indicators (supporting evidence)
    let mut has_plt_sections = false;
    let mut has_got_plt = false;
    let mut has_dynamic_relocations = false;
    
    // ==================== ARCHITECTURE DETECTION ====================
    
    // Detect bitness from ELF class
    let bitness = match elf.header.e_ident[4] {
        1 => 32, // ELFCLASS32
        2 => 64, // ELFCLASS64
        _ => 0,  // Unknown
    };
    
    let (arch_info, arch_short) = match elf.header.e_machine {
        goblin::elf::header::EM_386 => ("i386 (Intel 80386)", "i386"),
        goblin::elf::header::EM_68K => ("Motorola 68000", "m68k"),
        goblin::elf::header::EM_AARCH64 => ("AArch64 (ARM64)", "aarch64"),
        goblin::elf::header::EM_ALTERA_NIOS2 => ("Altera Nios II", "nios2"),
        goblin::elf::header::EM_AMDGPU => ("AMD GPU", "amdgpu"),
        goblin::elf::header::EM_ARM => ("ARM", "arm"),
        goblin::elf::header::EM_BPF => ("eBPF", "bpf"),
        goblin::elf::header::EM_CSKY => ("C-SKY", "csky"),
        goblin::elf::header::EM_IA_64 => ("Intel IA-64", "ia64"),
        goblin::elf::header::EM_LOONGARCH => ("LoongArch", "loongarch"),
        goblin::elf::header::EM_MICROBLAZE => ("Xilinx MicroBlaze", "microblaze"),
        goblin::elf::header::EM_MIPS => ("MIPS", "mips"),
        goblin::elf::header::EM_PARISC => ("HP PA-RISC", "parisc"),
        goblin::elf::header::EM_PPC64 => ("PowerPC64", "ppc64"),
        goblin::elf::header::EM_PPC => ("PowerPC", "ppc"),
        goblin::elf::header::EM_RISCV => ("RISC-V", "riscv"),
        goblin::elf::header::EM_S390 => ("IBM System/390", "s390"),
        goblin::elf::header::EM_SH => ("SuperH", "sh"),
        goblin::elf::header::EM_SPARC => ("SPARC", "sparc"),
        goblin::elf::header::EM_SPARCV9 => ("SPARC v9", "sparcv9"),
        goblin::elf::header::EM_VAX => ("VAX", "vax"),
        goblin::elf::header::EM_X86_64 => ("x86_64 (AMD64)", "x86_64"),
        goblin::elf::header::EM_XTENSA => ("Tensilica Xtensa", "xtensa"),
        _ => ("Unknown/Other", "unknown")
    };
    
    // Add architecture and bitness to indicators
    if bitness > 0 {
        primary_indicators.push(format!("Architecture: {}-bit {}", bitness, arch_info));
    } else {
        primary_indicators.push(format!("Architecture: {} (unknown bitness)", arch_info));
    }
    
    // Add endianness information
    let endianness = match elf.header.e_ident[5] {
        1 => "little-endian",
        2 => "big-endian",
        _ => "unknown endianness"
    };
    secondary_indicators.push(format!("Endianness: {}", endianness));
    
    // ==================== PRIMARY ANALYSIS ====================
    
    // Check 1: Program Headers - PT_INTERP (Most Reliable)
    for ph in &elf.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_INTERP => {
                has_pt_interp = true;
                primary_indicators.push("PT_INTERP program header found".to_string());
                
                // Extract interpreter path
                if let Ok(interp_str) = extract_interpreter_path(&buffer, ph) {
                    primary_indicators.push(format!("Dynamic linker: {}", interp_str));
                }
            }
            goblin::elf::program_header::PT_DYNAMIC => {
                has_pt_dynamic = true;
                primary_indicators.push("PT_DYNAMIC program header found".to_string());
            }
            _ => {}
        }
    }
    
    // Check 2: Dynamic Section (Critical)
    for section in &elf.section_headers {
        if section.sh_type == goblin::elf::section_header::SHT_DYNAMIC {
            has_dynamic_section = true;
            primary_indicators.push("SHT_DYNAMIC section found".to_string());
            break;
        }
    }
    
    // Check 3: NEEDED entries (Most Reliable)
    let mut is_static_pie = false;
    if let Some(dynamic) = &elf.dynamic {
        let needed_libs = extract_needed_libraries(dynamic, &elf.dynstrtab);
        if !needed_libs.is_empty() {
            has_needed_entries = true;
            primary_indicators.push(format!("NEEDED entries: {} shared libraries", needed_libs.len()));
            for lib in needed_libs {
                primary_indicators.push(format!("  → {}", lib));
            }
        } else if has_pt_dynamic || has_dynamic_section {
            // Has dynamic structures but no NEEDED entries = static-PIE
            is_static_pie = true;
            primary_indicators.push("Static-PIE detected: Dynamic structures present but no NEEDED entries".to_string());
        }
    }
    
    // Check 4: Dynamic Symbol Table (Critical)
    if !elf.dynsyms.is_empty() {
        has_dynamic_symbols = true;
        primary_indicators.push(format!("Dynamic symbol table with {} symbols", elf.dynsyms.len()));
    }
    
    // ==================== SECONDARY ANALYSIS ====================
    
    // Check 5: Dynamic-specific sections
    let mut section_counts = std::collections::HashMap::new();
    analyze_sections(&elf, &mut secondary_indicators, &mut section_counts, &mut has_plt_sections, &mut has_got_plt);
    
    // Check 6: Dynamic Relocations
    let relocation_info = analyze_relocations(&elf);
    if relocation_info.total > 0 {
        has_dynamic_relocations = true;
        secondary_indicators.push(format!("Dynamic relocations: {} total", relocation_info.total));
        
        if relocation_info.standard > 0 {
            secondary_indicators.push(format!("  • {} standard relocations", relocation_info.standard));
        }
        if relocation_info.with_addends > 0 {
            secondary_indicators.push(format!("  • {} relocations with addends", relocation_info.with_addends));
        }
        if relocation_info.plt > 0 {
            secondary_indicators.push(format!("  • {} PLT relocations", relocation_info.plt));
        }
    }
    
    // File type analysis with PIE detection
    analyze_file_type(&elf, &mut secondary_indicators, has_pt_interp, is_static_pie);
    
    // Check 8: Symbol Analysis with stripped detection
    let stripped = analyze_symbols(&elf, &mut secondary_indicators);
    
    // Check 9: Size analysis for static vs dynamic heuristics
    analyze_size_heuristics(file_size, &elf, &mut secondary_indicators, has_needed_entries);
    
    // ==================== DECISION LOGIC ====================
    
    // The key insight: static-PIE binaries have dynamic structures but no NEEDED entries
    // and no PT_INTERP (no dynamic linker)
    let is_static = if is_static_pie {
        // Static-PIE: has dynamic structures but is actually static
        true
    } else {
        // Traditional logic: no dynamic linking infrastructure = static
        !has_needed_entries && !has_pt_interp && !has_pt_dynamic && !has_dynamic_section && !has_dynamic_symbols
    };
    
    // Confidence calculation
    let confidence = calculate_confidence(
        has_needed_entries,
        has_pt_interp,
        has_pt_dynamic,
        has_dynamic_section,
        has_dynamic_symbols,
        has_dynamic_relocations,
        has_plt_sections,
        is_static,
        is_static_pie,
        stripped,
        &elf
    );
    
    // Combine all evidence
    evidence.extend(primary_indicators.clone());
    evidence.extend(secondary_indicators.clone());
    
    // Add final analysis
    let analysis = if is_static {
        "STATIC LINKING: No dynamic linking infrastructure found"
    } else {
        "DYNAMIC LINKING: Dynamic linking infrastructure detected"
    };
    evidence.push(analysis.to_string());
    
    // Add confidence explanation
    let confidence_explanation = match confidence {
        c if c >= 0.98 => "Very High - Definitive indicators present",
        c if c >= 0.90 => "High - Strong indicators present", 
        c if c >= 0.80 => "Good - Multiple supporting indicators",
        c if c >= 0.70 => "Moderate - Some indicators present",
        _ => "Low - Limited indicators available"
    };
    evidence.push(format!("Confidence: {:.1}% ({})", confidence * 100.0, confidence_explanation));
    
    Ok(StaticAnalysisResult {
        is_static,
        evidence,
        confidence,
        primary_indicators,
        secondary_indicators,
        file_size,
        stripped,
        bitness,
        architecture: arch_short.to_string(),
    })
}

// Helper function to extract interpreter path safely
fn extract_interpreter_path(buffer: &[u8], ph: &goblin::elf::ProgramHeader) -> Result<String, Box<dyn std::error::Error>> {
    let interp_offset = ph.p_offset as usize;
    let interp_size = ph.p_filesz as usize;
    
    if interp_offset >= buffer.len() || interp_size == 0 {
        return Err("Invalid interpreter offset or size".into());
    }
    
    let end_offset = interp_offset.saturating_add(interp_size);
    if end_offset > buffer.len() {
        return Err("Interpreter data exceeds buffer".into());
    }
    
    let interp_bytes = &buffer[interp_offset..end_offset];
    let interp_str = std::str::from_utf8(interp_bytes)?;
    Ok(interp_str.trim_end_matches('\0').to_string())
}

// Helper function to extract NEEDED libraries
fn extract_needed_libraries(dynamic: &goblin::elf::Dynamic, dynstrtab: &goblin::strtab::Strtab) -> Vec<String> {
    let mut needed_libs = Vec::new();
    
    for entry in dynamic.dyns.iter() {
        if entry.d_tag == goblin::elf::dynamic::DT_NEEDED {
            if let Some(lib_name) = dynstrtab.get_at(entry.d_val as usize) {
                needed_libs.push(lib_name.to_string());
            }
        }
    }
    
    needed_libs
}

// Relocation analysis structure
struct RelocationInfo {
    total: usize,
    standard: usize,
    with_addends: usize,
    plt: usize,
}

fn analyze_relocations(elf: &Elf) -> RelocationInfo {
    let standard = elf.dynrels.len();
    let with_addends = elf.dynrelas.len();
    let plt = elf.pltrelocs.len();
    
    RelocationInfo {
        total: standard + with_addends + plt,
        standard,
        with_addends,
        plt,
    }
}

// Enhanced section analysis
fn analyze_sections(
    elf: &Elf,
    secondary_indicators: &mut Vec<String>,
    section_counts: &mut std::collections::HashMap<String, usize>,
    has_plt_sections: &mut bool,
    has_got_plt: &mut bool
) {
    let dynamic_section_names = [
        (".plt", "Procedure Linkage Table"),
        (".plt.got", "PLT for GOT entries"),
        (".plt.sec", "PLT with security enhancements"),
        (".got", "Global Offset Table"),
        (".got.plt", "GOT for PLT entries"),
        (".dynstr", "Dynamic string table"),
        (".dynsym", "Dynamic symbol table"),
        (".gnu.version", "Symbol versioning"),
        (".gnu.version_r", "Version requirements"),
        (".gnu.version_d", "Version definitions"),
        (".rela.dyn", "Dynamic relocations (with addends)"),
        (".rela.plt", "PLT relocations (with addends)"),
        (".rel.dyn", "Dynamic relocations"),
        (".rel.plt", "PLT relocations"),
        (".hash", "Symbol hash table"),
        (".gnu.hash", "GNU hash table"),
        (".interp", "Interpreter information"),
        (".dynamic", "Dynamic linking information"),
    ];
    
    for sh in &elf.section_headers {
        if let Some(name_str) = elf.shdr_strtab.get_at(sh.sh_name) {
            for (section_name, description) in &dynamic_section_names {
                if name_str == *section_name {
                    secondary_indicators.push(format!("{}: {} (size: {} bytes)", 
                        section_name, description, sh.sh_size));
                    *section_counts.entry(section_name.to_string()).or_insert(0) += 1;
                    
                    match *section_name {
                        ".plt" | ".plt.got" | ".plt.sec" => *has_plt_sections = true,
                        ".got.plt" => {
                            *has_plt_sections = true;
                            *has_got_plt = true;
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
    }
}

// Enhanced file type analysis with PIE detection
fn analyze_file_type(elf: &Elf, secondary_indicators: &mut Vec<String>, has_pt_interp: bool, is_static_pie: bool) {
    let file_type_info = match elf.header.e_type {
        goblin::elf::header::ET_EXEC => {
            if elf.header.e_entry != 0 {
                "ET_EXEC with entry point (traditional executable)"
            } else {
                "ET_EXEC without entry point (unusual)"
            }
        }
        goblin::elf::header::ET_DYN => {
            if elf.header.e_entry != 0 {
                if is_static_pie {
                    "ET_DYN with entry point (static-PIE executable)"
                } else if has_pt_interp {
                    "ET_DYN with entry point (PIE executable)"
                } else {
                    "ET_DYN with entry point (shared library)"
                }
            } else {
                "ET_DYN without entry point (shared library)"
            }
        }
        goblin::elf::header::ET_REL => "ET_REL (relocatable object file)",
        goblin::elf::header::ET_CORE => "ET_CORE (core dump)",
        _ => "Unknown ELF type"
    };
    secondary_indicators.push(format!("File type: {}", file_type_info));
}

// Enhanced symbol analysis with stripped detection
fn analyze_symbols(elf: &Elf, secondary_indicators: &mut Vec<String>) -> bool {
    let static_symbol_count = elf.syms.len();
    let dynamic_symbol_count = elf.dynsyms.len();
    let mut stripped = true;
    
    // Check for debug symbols and common function symbols
    let mut has_debug_symbols = false;
    let mut has_main_symbols = false;
    
    for sym in &elf.syms {
        if let Some(name_str) = elf.strtab.get_at(sym.st_name) {
            if name_str == "main" || name_str == "_start" {
                has_main_symbols = true;
            }
            if name_str.starts_with("__debug") || name_str.contains("_debug") {
                has_debug_symbols = true;
            }
            if !name_str.is_empty() {
                stripped = false;
            }
        }
    }
    
    if static_symbol_count > 0 {
        secondary_indicators.push(format!("Static symbols: {}", static_symbol_count));
    }
    if dynamic_symbol_count > 0 {
        secondary_indicators.push(format!("Dynamic symbols: {}", dynamic_symbol_count));
    }
    
    if has_debug_symbols {
        secondary_indicators.push("Debug symbols present".to_string());
        stripped = false;
    }
    
    if has_main_symbols {
        secondary_indicators.push("Main entry symbols present".to_string());
    }
    
    secondary_indicators.push(format!("Binary: {}", if stripped { "stripped" } else { "not stripped" }));
    
    if static_symbol_count > 0 && dynamic_symbol_count > 0 {
        let ratio = static_symbol_count as f32 / dynamic_symbol_count as f32;
        secondary_indicators.push(format!("Symbol ratio (static/dynamic): {:.1}", ratio));
    }
    
    stripped
}

// Size-based heuristics
fn analyze_size_heuristics(file_size: u64, elf: &Elf, secondary_indicators: &mut Vec<String>, has_needed_entries: bool) {
    secondary_indicators.push(format!("File size: {} bytes ({:.1} KB)", file_size, file_size as f64 / 1024.0));
    
    let text_section_size = elf.section_headers.iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).map_or(false, |name| name == ".text"))
        .map(|sh| sh.sh_size)
        .unwrap_or(0);
    
    if text_section_size > 0 {
        secondary_indicators.push(format!("Text section size: {} bytes", text_section_size));
    }
    
    // Size-based heuristics
    if !has_needed_entries {
        if file_size > 1024 * 1024 {  // > 1MB
            secondary_indicators.push("Large size suggests static linking".to_string());
        } else if file_size < 50 * 1024 {  // < 50KB
            secondary_indicators.push("Small size suggests dynamic linking".to_string());
        }
    }
}

// Enhanced confidence calculation - Updated signature to match function call
fn calculate_confidence(
    has_needed_entries: bool,
    has_pt_interp: bool,
    has_pt_dynamic: bool,
    has_dynamic_section: bool,
    has_dynamic_symbols: bool,
    has_dynamic_relocations: bool,
    has_plt_sections: bool,
    is_static: bool,
    is_static_pie: bool,
    stripped: bool,
    elf: &Elf
) -> f32 {
    if has_needed_entries {
        0.99 // Highest confidence - NEEDED entries are definitive
    } else if has_pt_interp {
        0.98 // Very high confidence - interpreter is definitive
    } else if has_pt_dynamic || has_dynamic_section {
        0.95 // High confidence based on dynamic structures
    } else if has_dynamic_symbols {
        0.90 // Good confidence
    } else if has_dynamic_relocations || has_plt_sections {
        0.85 // Moderate confidence
    } else if is_static {
        // For static binaries, confidence depends on additional factors
        let mut confidence: f32 = 0.75;
        
        // Handle static-PIE case
        if is_static_pie {
            confidence = 0.95; // High confidence for static-PIE detection
        }
        
        // Increase confidence for large binaries (likely static)
        if elf.syms.len() > 100 {
            confidence += 0.05;
        }
        
        // Decrease confidence for stripped binaries (harder to analyze)
        if stripped {
            confidence -= 0.05;
        }
        
        // Check for static-specific patterns
        let has_static_main = elf.syms.iter().any(|sym| {
            elf.strtab.get_at(sym.st_name).map_or(false, |name| name == "main")
        });
        
        if has_static_main {
            confidence += 0.10;
        }
        
        confidence.min(0.95_f32).max(0.60_f32)
    } else {
        0.70 // Lower confidence
    }
}

fn print_usage() {
    let program_name = env::args().next().unwrap_or_else(|| "elf-static-check".to_string());
    eprintln!("Usage: {} [OPTIONS] <elf-file>", program_name);
    eprintln!();
    eprintln!("Analyze ELF binary linking type (static vs dynamic).");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -r, --result     Show detailed analysis with evidence");
    eprintln!("  -v, --verbose    Show verbose output with all indicators");
    eprintln!("  -s, --simple     Show simple output (static/dynamic/error)");
    eprintln!("  -c, --confidence Show confidence score");
    eprintln!("  -a, --arch       Show architecture and bitness information");
    eprintln!("  -q, --quiet      Suppress non-essential output");
    eprintln!("  -h, --help       Show this help message");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0    Binary is statically linked");
    eprintln!("  1    Binary is dynamically linked");
    eprintln!("  2    Error (file not found, invalid ELF, etc.)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} /bin/ls                    # Simple check", program_name);
    eprintln!("  {} -r /bin/ls                 # Detailed analysis", program_name);
    eprintln!("  {} -v /usr/bin/gcc            # Verbose output", program_name);
    eprintln!("  {} -a /usr/local/bin/static   # Show architecture info", program_name);
    eprintln!("  {} -c /bin/bash               # Show confidence", program_name);
    eprintln!("  {} -q /bin/bash               # Quiet mode", program_name);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        process::exit(2);
    }
    
    let mut show_result = false;
    let mut verbose = false;
    let mut simple = false;
    let mut show_confidence = false;
    let mut show_arch = false;
    let mut quiet = false;
    let mut file_path = "";
    
    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--result" => show_result = true,
            "-v" | "--verbose" => verbose = true,
            "-s" | "--simple" => simple = true,
            "-c" | "--confidence" => show_confidence = true,
            "-a" | "--arch" => show_arch = true,
            "-q" | "--quiet" => quiet = true,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            arg if arg.starts_with('-') => {
                if simple {
                    println!("error");
                } else {
                    eprintln!("Error: Unknown option '{}'", arg);
                    print_usage();
                }
                process::exit(2);
            }
            _ => {
                if file_path.is_empty() {
                    file_path = &args[i];
                } else {
                    if simple {
                        println!("error");
                    } else {
                        eprintln!("Error: Multiple file paths specified");
                        print_usage();
                    }
                    process::exit(2);
                }
            }
        }
        i += 1;
    }
    
    if file_path.is_empty() {
        if simple {
            println!("error");
        } else {
            eprintln!("Error: No file path specified");
            print_usage();
        }
        process::exit(2);
    }
    
    // Validate file exists and resolve to canonical path
    let path = std::path::Path::new(file_path);
    if !path.exists() {
        if simple {
            println!("error");
        } else {
            eprintln!("Error: File '{}' not found", file_path);
        }
        process::exit(2);
    }
    
    // Resolve to canonical/real path
    let canonical_path = match path.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            if simple {
                println!("error");
            } else {
                eprintln!("Error: Cannot resolve path '{}': {}", file_path, e);
            }
            process::exit(2);
        }
    };
    
    let canonical_path_str = canonical_path.to_string_lossy();
    
    match analyze_elf_static_linking(&canonical_path_str) {
        Ok(result) => {
            if simple {
                println!("{}", if result.is_static { "static" } else { "dynamic" });
            } else if verbose {
                println!("=== ELF Static/Dynamic Analysis ===");
                println!("File: {}", canonical_path_str);
                println!("Result: {} LINKING", if result.is_static { "STATIC" } else { "DYNAMIC" });
                println!("Architecture: {}-bit {}", result.bitness, result.architecture);
                println!("Confidence: {:.1}%", result.confidence * 100.0);
                println!("File size: {:.1} KB", result.file_size as f64 / 1024.0);
                println!("Stripped: {}", if result.stripped { "Yes" } else { "No" });
                println!();
                
                if !result.primary_indicators.is_empty() {
                    println!("Primary Indicators (Definitive):");
                    for indicator in &result.primary_indicators {
                        println!("  ✓ {}", indicator);
                    }
                    println!();
                }
                
                if !result.secondary_indicators.is_empty() {
                    println!("Secondary Indicators (Supporting):");
                    for indicator in &result.secondary_indicators {
                        println!("  • {}", indicator);
                    }
                    println!();
                }
                
                println!("Analysis Summary:");
                println!("  The binary is {} linked with {:.1}% confidence.",
                    if result.is_static { "STATICALLY" } else { "DYNAMICALLY" },
                    result.confidence * 100.0);
                    
            } else if show_result || show_confidence || show_arch {
                println!("File: {}", canonical_path_str);
                println!("Linking: {}", if result.is_static { "Static" } else { "Dynamic" });
                if show_arch {
                    println!("Architecture: {}-bit {}", result.bitness, result.architecture);
                }
                if show_confidence {
                    println!("Confidence: {:.1}%", result.confidence * 100.0);
                }
                if show_result {
                    println!();
                    println!("Evidence:");
                    for evidence in &result.evidence {
                        println!("  • {}", evidence);
                    }
                }
            } else if quiet {
                println!("{}", if result.is_static { "static" } else { "dynamic" });
            } else {
                // Default output with architecture info
                println!("{}: {} {}-bit {} (confidence: {:.1}%)", 
                    canonical_path_str,
                    if result.is_static { "static" } else { "dynamic" },
                    result.bitness,
                    result.architecture,
                    result.confidence * 100.0);
            }
            
            process::exit(if result.is_static { 0 } else { 1 });
        }
        Err(e) => {
            if simple {
                println!("error");
            } else {
                eprintln!("Error analyzing '{}': {}", canonical_path_str, e);
            }
            process::exit(2);
        }
    }
}