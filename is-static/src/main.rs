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
}

fn analyze_elf_static_linking(file_path: &str) -> Result<StaticAnalysisResult, Box<dyn std::error::Error>> {
    let buffer = fs::read(file_path)?;
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
    
    let arch_info = match elf.header.e_machine {
        goblin::elf::header::EM_386 => "i386 (Intel 80386)",
        goblin::elf::header::EM_68K => "Motorola 68000",
        goblin::elf::header::EM_AARCH64 => "AArch64 (ARM64)",
        goblin::elf::header::EM_ALTERA_NIOS2 => "Altera Nios II",
        goblin::elf::header::EM_AMDGPU => "AMD GPU",
        goblin::elf::header::EM_ARM => "ARM",
        goblin::elf::header::EM_BPF => "eBPF",
        goblin::elf::header::EM_CSKY => "C-SKY",
        goblin::elf::header::EM_IA_64 => "Intel IA-64",
        goblin::elf::header::EM_LOONGARCH => "LoongArch",
        goblin::elf::header::EM_MIPS => "MIPS",
        goblin::elf::header::EM_PARISC => "HP PA-RISC",
        goblin::elf::header::EM_PPC64 => "PowerPC64",
        goblin::elf::header::EM_PPC => "PowerPC",
        goblin::elf::header::EM_RISCV => "RISC-V",
        goblin::elf::header::EM_S390 => "IBM System/390",
        goblin::elf::header::EM_SH => "SuperH",
        goblin::elf::header::EM_SPARC => "SPARC",
        goblin::elf::header::EM_SPARCV9 => "SPARC v9",
        goblin::elf::header::EM_VAX => "VAX",
        goblin::elf::header::EM_X86_64 => "x86_64 (AMD64)",
        goblin::elf::header::EM_XTENSA => "Tensilica Xtensa",
        _ => "Unknown/Other"
    };
    
    secondary_indicators.push(format!("Architecture: {}", arch_info));
    
    // ==================== PRIMARY ANALYSIS ====================
    
    // Check 1: Program Headers - PT_INTERP (Most Reliable)
    for ph in &elf.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_INTERP => {
                has_pt_interp = true;
                primary_indicators.push("PT_INTERP program header found".to_string());
                
                // Extract interpreter path (equivalent to readelf -p '.interp')
                let interp_offset = ph.p_offset as usize;
                let interp_size = ph.p_filesz as usize;
                if interp_offset < buffer.len() && interp_offset + interp_size <= buffer.len() {
                    let interp_bytes = &buffer[interp_offset..interp_offset + interp_size];
                    if let Ok(interp_str) = std::str::from_utf8(interp_bytes) {
                        let interp_clean = interp_str.trim_end_matches('\0').to_string();
                        primary_indicators.push(format!("Dynamic linker: {}", interp_clean));
                    }
                }
            }
            goblin::elf::program_header::PT_DYNAMIC => {
                has_pt_dynamic = true;
                primary_indicators.push("PT_DYNAMIC program header found".to_string());
            }
            _ => {}
        }
    }
    
    // Check 2: Dynamic Section (Critical - equivalent to readelf --dynamic)
    for section in &elf.section_headers {
        if section.sh_type == goblin::elf::section_header::SHT_DYNAMIC {
            has_dynamic_section = true;
            primary_indicators.push("SHT_DYNAMIC section found".to_string());
            break;
        }
    }
    
    // Check 3: NEEDED entries (Most Reliable - equivalent to readelf --dynamic | grep NEEDED)
    // This is the most reliable indicator of dynamic linking
    if let Some(dynamic) = &elf.dynamic {
        let mut needed_count = 0;
        let mut needed_libs = Vec::new();
        
        for entry in dynamic.dyns.iter() {
            if entry.d_tag == goblin::elf::dynamic::DT_NEEDED {
                needed_count += 1;
                has_needed_entries = true;
                
                // Try to get the library name from dynstrtab
                if let Some(lib_name) = elf.dynstrtab.get_at(entry.d_val as usize) {
                    needed_libs.push(lib_name.to_string());
                }
            }
        }
        
        if has_needed_entries {
            primary_indicators.push(format!("NEEDED entries: {} shared libraries", needed_count));
            for lib in needed_libs {
                primary_indicators.push(format!("  → {}", lib));
            }
        }
    }
    
    // Check 4: Dynamic Symbol Table (Critical)
    if !elf.dynsyms.is_empty() {
        has_dynamic_symbols = true;
        primary_indicators.push(format!("Dynamic symbol table with {} symbols", elf.dynsyms.len()));
    }
    
    // ==================== SECONDARY ANALYSIS ====================
    
    // Check 5: Dynamic-specific sections
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
    
    for (section_name, description) in &dynamic_section_names {
        for sh in &elf.section_headers {
            if let Some(name_str) = elf.shdr_strtab.get_at(sh.sh_name) {
                if name_str == *section_name {
                    secondary_indicators.push(format!("{}: {}", section_name, description));
                    match *section_name {
                        ".plt" | ".plt.got" | ".plt.sec" => has_plt_sections = true,
                        ".got.plt" => {
                            has_plt_sections = true;
                            has_got_plt = true;
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
    }
    
    // Check 6: Dynamic Relocations
    let total_dynamic_relocations = elf.dynrels.len() + elf.dynrelas.len() + elf.pltrelocs.len();
    if total_dynamic_relocations > 0 {
        has_dynamic_relocations = true;
        secondary_indicators.push(format!("Dynamic relocations: {} total", total_dynamic_relocations));
        
        if !elf.dynrels.is_empty() {
            secondary_indicators.push(format!("  • {} standard relocations", elf.dynrels.len()));
        }
        if !elf.dynrelas.is_empty() {
            secondary_indicators.push(format!("  • {} relocations with addends", elf.dynrelas.len()));
        }
        if !elf.pltrelocs.is_empty() {
            secondary_indicators.push(format!("  • {} PLT relocations", elf.pltrelocs.len()));
        }
    }
    
    // Check 7: File Type Analysis
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
                "ET_DYN with entry point (PIE executable or shared library)"
            } else {
                "ET_DYN without entry point (shared library)"
            }
        }
        goblin::elf::header::ET_REL => "ET_REL (relocatable object file)",
        goblin::elf::header::ET_CORE => "ET_CORE (core dump)",
        _ => "Unknown ELF type"
    };
    secondary_indicators.push(format!("File type: {}", file_type_info));
    
    // Check 8: Symbol Analysis
    let static_symbol_count = elf.syms.len();
    let dynamic_symbol_count = elf.dynsyms.len();
    
    if static_symbol_count > 0 {
        secondary_indicators.push(format!("Static symbols: {}", static_symbol_count));
    }
    if dynamic_symbol_count > 0 {
        secondary_indicators.push(format!("Dynamic symbols: {}", dynamic_symbol_count));
    }
    
    if static_symbol_count > 0 && dynamic_symbol_count > 0 {
        let ratio = static_symbol_count as f32 / dynamic_symbol_count as f32;
        secondary_indicators.push(format!("Symbol ratio (static/dynamic): {:.1}", ratio));
    }
    
    // Check 9: Look for common static/dynamic patterns
    let mut has_static_patterns = false;
    let static_patterns = [
        ("__libc_start_main", "glibc entry point"),
        ("_start", "program entry point"),
        ("main", "main function"),
        ("__static_initialization_and_destruction_0", "static initialization"),
    ];
    
    for (pattern, description) in &static_patterns {
        for sym in &elf.syms {
            if let Some(name_str) = elf.strtab.get_at(sym.st_name) {
                if name_str == *pattern {
                    secondary_indicators.push(format!("Static pattern: {} ({})", pattern, description));
                    has_static_patterns = true;
                    break;
                }
            }
        }
    }
    
    // ==================== DECISION LOGIC ====================
    
    // Most reliable indicators in order of precedence:
    // 1. NEEDED entries (readelf --dynamic | grep NEEDED)
    // 2. PT_INTERP program header (readelf -p '.interp')
    // 3. PT_DYNAMIC program header
    // 4. Dynamic section presence
    // 5. Dynamic symbols
    
    let is_static = if has_needed_entries {
        // Most reliable: Has NEEDED entries -> Definitely Dynamic
        false
    } else if has_pt_interp {
        // Very reliable: Has interpreter -> Dynamic
        false
    } else if has_pt_dynamic {
        // Very reliable: Has PT_DYNAMIC -> Dynamic
        false
    } else if has_dynamic_section {
        // Reliable: Has dynamic section -> Dynamic  
        false
    } else if has_dynamic_symbols {
        // Reliable: Has dynamic symbols -> Dynamic
        false
    } else if has_dynamic_relocations {
        // Less reliable: Could be static with relocations
        false
    } else if has_plt_sections || has_got_plt {
        // Less reliable: PLT/GOT structures usually indicate dynamic
        false
    } else {
        // No dynamic indicators found -> Static
        true
    };
    
    // Calculate confidence based on the strength of indicators
    let confidence = if has_needed_entries {
        0.99 // Highest confidence - NEEDED entries are definitive
    } else if has_pt_interp {
        0.98 // Very high confidence - interpreter is definitive
    } else if has_pt_dynamic || has_dynamic_section {
        0.95 // High confidence based on dynamic structures
    } else if has_dynamic_symbols {
        0.90 // Good confidence
    } else if has_dynamic_relocations || has_plt_sections {
        0.85 // Moderate confidence
    } else if is_static && has_static_patterns && dynamic_symbol_count == 0 {
        0.90 // Good confidence for static
    } else if is_static && static_symbol_count > 0 && dynamic_symbol_count == 0 {
        0.85 // Moderate confidence for static
    } else {
        0.75 // Lower confidence
    };
    
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
    })
}

fn print_usage() {
    eprintln!("Usage: {} [OPTIONS] <elf-file>", env::args().next().unwrap_or_else(|| "elf-static-check".to_string()));
    eprintln!();
    eprintln!("Analyze ELF binary linking type (static vs dynamic).");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -r, --result    Show detailed analysis with evidence");
    eprintln!("  -v, --verbose   Show verbose output with all indicators");
    eprintln!("  -s, --simple    Show simple output (static/dynamic/error)");
    eprintln!("  -c, --confidence Show confidence score");
    eprintln!("  -h, --help      Show this help message");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0    Binary is statically linked");
    eprintln!("  1    Binary is dynamically linked");
    eprintln!("  2    Error (file not found, invalid ELF, etc.)");
    eprintln!();
    let program_name = env::args().next().unwrap_or_else(|| "elf-static-check".to_string());
    eprintln!("Examples:");
    eprintln!("  {} /bin/ls                    # Simple check", program_name);
    eprintln!("  {} -r /bin/ls                 # Detailed analysis", program_name);
    eprintln!("  {} -v /usr/bin/gcc            # Verbose output", program_name);
    eprintln!("  {} -c /usr/local/bin/static   # Show confidence", program_name);
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
    let mut file_path = "";
    
    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--result" => show_result = true,
            "-v" | "--verbose" => verbose = true,
            "-s" | "--simple" => simple = true,
            "-c" | "--confidence" => show_confidence = true,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            arg if arg.starts_with('-') => {
                eprintln!("Error: Unknown option '{}'", arg);
                print_usage();
                process::exit(2);
            }
            _ => {
                if file_path.is_empty() {
                    file_path = &args[i];
                } else {
                    eprintln!("Error: Multiple file paths specified");
                    print_usage();
                    process::exit(2);
                }
            }
        }
        i += 1;
    }
    
    if file_path.is_empty() {
        eprintln!("Error: No file path specified");
        print_usage();
        process::exit(2);
    }
    
    // Validate file exists and is readable
    if !std::path::Path::new(file_path).exists() {
        eprintln!("Error: File '{}' not found", file_path);
        process::exit(2);
    }
    
    match analyze_elf_static_linking(file_path) {
        Ok(result) => {
            if simple {
                println!("{}", if result.is_static { "static" } else { "dynamic" });
            } else if verbose {
                println!("=== ELF Static/Dynamic Analysis ===");
                println!("File: {}", file_path);
                println!("Result: {} LINKING", if result.is_static { "STATIC" } else { "DYNAMIC" });
                println!("Confidence: {:.1}%", result.confidence * 100.0);
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
                    
            } else if show_result || show_confidence {
                println!("File: {}", file_path);
                println!("Linking: {}", if result.is_static { "Static" } else { "Dynamic" });
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
            } else {
                // Default output
                println!("{}: {} (confidence: {:.1}%)", 
                    file_path,
                    if result.is_static { "static" } else { "dynamic" },
                    result.confidence * 100.0);
            }
            
            process::exit(if result.is_static { 0 } else { 1 });
        }
        Err(e) => {
            if simple {
                println!("error");
            } else {
                eprintln!("Error analyzing '{}': {}", file_path, e);
            }
            process::exit(2);
        }
    }
}