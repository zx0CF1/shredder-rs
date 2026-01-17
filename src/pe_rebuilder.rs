//! PE Rebuilder - Section injection and NT Header orchestration.
use crate::error::ShredderError;
use crate::pe_parser::ParsedPE;
use crate::shredder::{assemble_mutated_flow, ShreddedCode};
use exe::pe::PE;
use exe::types::{CChar, Offset, RVA};
use exe::Buffer;
use exe::{ImageSectionHeader, SectionCharacteristics};
use std::path::Path;

/// Reconstructs the binary by injecting a new execution node (.shred).
pub fn rebuild_pe(
    source: &ParsedPE,
    shredded: &ShreddedCode,
    target_base_va: u64,
    out_path: &Path,
) -> Result<(), ShredderError> {
    let mut pe = source.raw_instance.clone();

    // 1. Generate payload for the new Virtual Address
    let payload = assemble_mutated_flow(shredded, target_base_va);

    println!("[*] Patching NT Headers and expanding section table...");

    // 2. Metadata calculation for the new segment
    let new_rva = (target_base_va - source.image_base) as u32;
    let raw_offset = source.next_available_file_offset();
    let file_alignment = 0x200; // Standard PE file alignment
    let aligned_raw_size = (payload.len() as u32 + (file_alignment - 1)) & !(file_alignment - 1);

    // 3. Header Construction (.shred)
    let mut hdr = ImageSectionHeader::default();
    let mut name_buf = [CChar(0); 8];
    for (i, b) in ".shred".as_bytes().iter().enumerate().take(8) {
        name_buf[i] = CChar(*b);
    }

    hdr.name = name_buf;
    hdr.virtual_size = payload.len() as u32;
    hdr.virtual_address = RVA(new_rva);
    hdr.size_of_raw_data = aligned_raw_size;
    hdr.pointer_to_raw_data = Offset(raw_offset);
    hdr.characteristics = SectionCharacteristics::CNT_CODE
        | SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ;

    // 4. Update Image State
    let new_entry_rva = (shredded.entry_point - source.image_base) as u32;

    {
        let nt = pe.get_valid_mut_nt_headers_64().map_err(|e| {
            ShredderError::RebuildError(format!("NT Header access denied: {:?}", e))
        })?;

        nt.file_header.number_of_sections += 1;

        // Recalculate SizeOfImage based on new section bounds
        let section_align = nt.optional_header.section_alignment;
        nt.optional_header.size_of_image =
            (new_rva + payload.len() as u32 + section_align - 1) & !(section_align - 1);

        // Redirect EntryPoint to our mutated entry node
        nt.optional_header.address_of_entry_point = RVA(new_entry_rva);

        // Invalidate Checksum (Commonly required for modified binaries)
        nt.optional_header.checksum = 0;
    }

    // 5. Buffer Assembly
    let mut final_bin = pe.as_slice().to_vec();
    let required_size = raw_offset as usize + aligned_raw_size as usize;
    if final_bin.len() < required_size {
        final_bin.resize(required_size, 0);
    }

    // Write the new section header into the table
    let section_table_off = pe.get_section_table_offset().unwrap().0 as usize;
    let section_count = (source.raw_instance.get_section_table().unwrap().len() + 1) as usize;
    let hdr_pos =
        section_table_off + (section_count - 1) * std::mem::size_of::<ImageSectionHeader>();

    let hdr_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const _) as *const u8,
            std::mem::size_of::<ImageSectionHeader>(),
        )
    };

    final_bin[hdr_pos..hdr_pos + hdr_slice.len()].copy_from_slice(hdr_slice);

    // Commit mutated code to disk offset
    final_bin[raw_offset as usize..raw_offset as usize + payload.len()].copy_from_slice(&payload);

    std::fs::write(out_path, &final_bin)
        .map_err(|e| ShredderError::RebuildError(format!("Disk write failed: {:?}", e)))?;

    println!(
        "[+] Injection successful: .shred section mapped at RVA 0x{:X}",
        new_rva
    );
    Ok(())
}
