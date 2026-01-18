# Shredder-RS

A polymorphic mutation engine for x86_64 binaries.

## Overview
Shredder-RS implements instruction-level shredding to defeat static analysis. By breaking the linear flow of the code and injecting randomized junk nodes, it forces disassemblers to follow a complex graph of JMP-linked instructions.

## Core Mechanism: Instruction Shredding
Unlike basic obfuscators that only add junk code, **Shredder-RS** deconstructs the original instruction stream into isolated functional nodes.

1. **Decoding:** Full x86_64 disassembly using `iced-x86`.
2. **Fragmentation:** Each instruction is wrapped in a "Mutation Node".
3. **Entropy Injection:** Nodes are physically shuffled in a new PE section.
4. **Control Flow Linking:** Nodes are re-connected via relative jumps, creating a "spaghetti" CFG (Control Flow Graph) that disrupts linear sweep disassemblers.

## Key Features
- **Context-Aware Mutation:** Preserves EFLAGS and volatile registers via context-sandwiching (Push/Popfq).
- **Non-Linear Layout:** Randomized physical instruction placement to defeat pattern matching.
- **PE Support:** Automated section injection (`.shred`) and EntryPoint hijacking.

## Documentation
For deep technical details, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Disclaimer
This project is developed for **educational and research purposes only**. Its goal is to explore polymorphic techniques and binary hardening. The author is not responsible for any misuse of this tool.

## Build Requirements
- Rust 1.70+ (Stable)
- MSVC Linker (Required for PE reconstruction on Windows)