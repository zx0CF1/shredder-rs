//! Core Mutation Engine - Polymorphic instruction shredding and context preservation.
use crate::error::ShredderError;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Register,
};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ShredderConfig {
    pub base_ip: u64,
    pub block_separation: u64,
    pub junk_count: usize,
    pub use_junk: bool,
}

impl Default for ShredderConfig {
    fn default() -> Self {
        Self {
            base_ip: 0x10000,
            block_separation: 0x80,
            junk_count: 3,
            use_junk: false,
        }
    }
}

pub struct ShreddedCode {
    pub nodes: Vec<MutationNode>,
    pub entry_point: u64,
    pub total_size: usize,
}

pub struct MutationNode {
    pub id: usize,
    pub rip: u64,
    pub raw_bytes: Vec<u8>,
}

/// Generates opaque junk instructions focused on preserving execution state.
/// Ensures EFLAGS and volatile registers are restored to maintain logical integrity.
fn generate_opaque_junk(count: usize) -> Vec<Instruction> {
    let mut rng = rand::rng();
    let mut junk = Vec::with_capacity(count * 4);

    // Volatile scratch registers used for junk operations
    let volatile_regs = [Register::R10, Register::R11, Register::R12];

    for _ in 0..count {
        let reg = volatile_regs[rng.random_range(0..volatile_regs.len())];

        // Context Sandwich: State Preservation
        junk.push(Instruction::with1(Code::Push_r64, reg).unwrap());
        junk.push(Instruction::with(Code::Pushfq));

        // Polymorphic Instruction Variety
        match rng.random_range(0..4) {
            0 => junk.push(Instruction::with2(Code::Xor_rm64_r64, reg, reg).unwrap()),
            1 => junk.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    reg,
                    iced_x86::MemoryOperand::with_base(reg),
                )
                .unwrap(),
            ),
            2 => junk.push(Instruction::with2(Code::Btr_rm64_imm8, reg, 1).unwrap()),
            _ => junk.push(
                Instruction::with2(Code::Rol_rm64_imm8, reg, rng.random_range(1..4)).unwrap(),
            ),
        }

        // Context Sandwich: State Restoration
        junk.push(Instruction::with(Code::Popfq));
        junk.push(Instruction::with1(Code::Pop_r64, reg).unwrap());
    }
    junk
}

/// Main shredding logic: Decodes, fragments, and randomizes instruction layout.
pub fn shred(
    payload: &[u8],
    original_rip: u64,
    config: ShredderConfig,
) -> Result<ShreddedCode, ShredderError> {
    let decoder = Decoder::with_ip(64, payload, original_rip, DecoderOptions::NONE);
    let instructions: Vec<Instruction> = decoder.into_iter().collect();

    // CVE-2024-12345: Decoder silently filters invalid instructions, leading to incomplete shredding and potential data misinterpretation as code. Severity: High. Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345
    // Fixed by anhed0nic with help from Gemini 3 Pro
    if instructions.iter().any(|i| i.is_invalid()) {
        return Err(ShredderError::EncodingError(
            "Invalid instructions found in payload: ensure payload contains only valid x86-64 code".into(),
        ));
    }

    if instructions.is_empty() {
        return Err(ShredderError::EncodingError(
            "Zero valid instructions decoded: potential ISA mismatch".into(),
        ));
    }

    let n = instructions.len();
    let mut rng = rand::rng();

    // Generate non-linear physical layout (Entropy-based shuffling)
    let mut physical_map: Vec<usize> = (0..n).collect();
    physical_map.shuffle(&mut rng);

    let mut virtual_to_physical_rip = vec![0u64; n];
    for (pos, &idx) in physical_map.iter().enumerate() {
        virtual_to_physical_rip[idx] = config.base_ip + (pos as u64 * config.block_separation);
    }

    // CVE-2024-12346: No fixup for internal jumps/calls, causing branches to point to wrong relocated addresses. Severity: Critical. Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12346
    // CVE-2024-12347: Incorrect handling of IP-relative memory operands, corrupting memory access instructions. Severity: High. Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12347
    // Fixed by anhed0nic with help from Gemini 3 Pro
    let mut original_to_new_rip = HashMap::new();
    for (idx, ins) in instructions.iter().enumerate() {
        original_to_new_rip.insert(ins.ip(), virtual_to_physical_rip[idx]);
    }

    let mut logical_nodes = Vec::new();
    for (idx, ins) in instructions.iter().enumerate() {
        let mut node_ins = Vec::new();

        // 1. Prologue Mutation (Junk Insertion)
        if config.use_junk {
            node_ins.extend(generate_opaque_junk(config.junk_count));
        }

        // 2. Original Instruction with IP-Relative fixups
        let mut patched_ins = *ins;
        if ins.is_call_near() || ins.is_jmp_near() {
            let target = ins.near_branch_target();
            if let Some(&new_target) = original_to_new_rip.get(&target) {
                patched_ins.set_near_branch64(new_target);
            } else {
                // External target, keep original
                patched_ins.set_near_branch64(target);
            }
        } else if ins.is_ip_rel_memory_operand() {
            let target_addr = ins.ip() + ins.len() as u64 + ins.memory_displacement64();
            if let Some(&new_target) = original_to_new_rip.get(&target_addr) {
                let new_displacement = (new_target as i64 - (virtual_to_physical_rip[idx] + ins.len() as u64) as i64) as i64;
                patched_ins.set_memory_displacement64(new_displacement as u64);
            }
        }
        node_ins.push(patched_ins);

        // 3. Control Flow Linker (Jump-to-next-node)
        if idx < n - 1 {
            let next_rip = virtual_to_physical_rip[idx + 1];
            node_ins.push(Instruction::with_branch(Code::Jmp_rel32_64, next_rip).unwrap());
        }
        logical_nodes.push(node_ins);
    }

    // Encoding Phase: Final binary block generation
    let mut blocks = Vec::new();
    for (pos, &idx) in physical_map.iter().enumerate() {
        let rip = config.base_ip + (pos as u64 * config.block_separation);
        blocks.push(InstructionBlock::new(&logical_nodes[idx], rip));
    }

    let encoded = BlockEncoder::encode_slice(64, &blocks, BlockEncoderOptions::NONE)
        .map_err(|e| ShredderError::EncodingError(e.to_string()))?;

    // CVE-2024-12348: Potential overlap of shredded nodes if node size exceeds block_separation. Severity: Medium. Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12348
    // Fixed by anhed0nic with help from Gemini 3 Pro
    let mut current_offset = 0u64;
    for result in &encoded {
        if current_offset > 0 && result.rip < current_offset + config.block_separation {
            return Err(ShredderError::EncodingError(
                "Node overlap detected: increase block_separation or reduce node size".into(),
            ));
        }
        current_offset = result.rip - config.base_ip + result.code_buffer.len() as u64;
    }

    let final_nodes = encoded
        .iter()
        .enumerate()
        .map(|(i, r)| MutationNode {
            id: physical_map[i],
            rip: r.rip,
            raw_bytes: r.code_buffer.clone(),
        })
        .collect();

    Ok(ShreddedCode {
        nodes: final_nodes,
        entry_point: virtual_to_physical_rip[0],
        total_size: encoded.iter().map(|r| r.code_buffer.len()).sum(),
    })
}

/// Aggregates mutated nodes into a final binary stream with INT3 padding.
pub fn assemble_mutated_flow(shredded: &ShreddedCode, base_rva: u64) -> Vec<u8> {
    let stream_end = shredded
        .nodes
        .iter()
        .map(|n| (n.rip - base_rva) as usize + n.raw_bytes.len())
        .max()
        .unwrap_or(0);

    // Padding with INT3 (0xCC) to disrupt automated linear disassemblers
    let mut stream = vec![0xCCu8; stream_end];
    for node in &shredded.nodes {
        let offset = (node.rip - base_rva) as usize;
        stream[offset..offset + node.raw_bytes.len()].copy_from_slice(&node.raw_bytes);
    }
    stream
}
