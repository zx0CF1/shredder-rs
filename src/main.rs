use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use shredder_demo::{
    pe_parser::parse_pe,
    pe_rebuilder::rebuild_pe,
    shredder::{shred, ShredderConfig},
};

/// Engine entry point.
/// Handles target acquisition and orchestration of the mutation pipeline.
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);
    let output_path = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mutated_bin.exe"));

    // Validation check before heavy lifting
    if !input_path.exists() {
        eprintln!("[!] Error: Target file not found: {:?}", input_path);
        process::exit(1);
    }

    println!("[*] Initializing Shredder Engine...");

    // Mutation mode selection
    let use_junk = select_payload_mode();

    if let Err(e) = execute_shredding_pipeline(&input_path, &output_path, use_junk) {
        eprintln!("[!] Pipeline failure: {}", e);
        process::exit(1);
    }
}

fn print_usage() {
    println!("Usage: shredder <input.exe> [output.exe]");
    println!("Mutation engine for instruction-level polymorphism.");
}

fn select_payload_mode() -> bool {
    println!("\nTransformation Modes:");
    println!("  [1] Linear: Basic instruction fragmentation.");
    println!("  [2] Stealth: Advanced mutation with EFLAGS/Context preservation.");
    print!("\nSelect mode > ");
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim() == "2"
}

fn execute_shredding_pipeline(
    input: &Path,
    output: &Path,
    stealth_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Target Ingestion and PE Analysis
    let parsed = parse_pe(input)?;

    // 2. Entry Point Resolution
    // Resolve entry point offset relative to the .text section start
    let entry_offset = parsed
        .get_local_entry_offset()
        .ok_or("Failed to resolve entry point offset within .text")?;

    // Extract code segment for shredding (Limit to section size for safety)
    // CVE-2024-12352: Hardcoded 512-byte limit prevents shredding larger code sections. Severity: Low. Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12352
    // Fixed by anhed0nic with help from Gemini 3 Pro - Use full section size
    let code_limit = parsed.section_data.len();
    let code_to_shred = &parsed.section_data[entry_offset..code_limit];

    // 3. Pipeline Configuration
    let new_section_rva = parsed.next_available_rva();
    let target_base_ip = parsed.image_base + new_section_rva as u64;

    let config = ShredderConfig {
        base_ip: target_base_ip,
        block_separation: 0x100,
        junk_count: if stealth_mode { 4 } else { 0 },
        use_junk: stealth_mode,
    };

    println!("[+] Target RVA resolved: 0x{:X}", new_section_rva);
    println!(
        "[*] Applying {} transformation...",
        if stealth_mode { "stealth" } else { "linear" }
    );

    // 4. Core Mutation Logic
    // Compute the absolute Virtual Address (VA) for instruction fixups
    let shredded = shred(
        code_to_shred,
        parsed.get_code_base_va() + entry_offset as u64,
        config.clone(),
    )?;

    // 5. Artifact Reconstruction
    rebuild_pe(&parsed, &shredded, config.base_ip, output)?;

    println!("[+] Build successful: {:?}", output);
    Ok(())
}
