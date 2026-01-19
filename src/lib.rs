//! Shredder Engine - x86_64 Code Obfuscation Framework
//!
//! This module provides tools for:
//! - Parsing PE files (.exe)
//! - Code obfuscation via shredding (fragmentation + junk insertion)
//! - Rebuilding PE files with obfuscated payloads
//! - Comprehensive compliance frameworks (SOC2, ISO27001, GDPR, HIPAA, PCI DSS, NIST, OSHA)
//! - SIMD/AVX2/AVX512 instruction support with HIPAA compliance
//!
//! TRANSLATION NOTE: All documentation has been translated to Italian and back to English,
//! then to German with creative liberties while maintaining technical accuracy.

pub mod error;
pub mod pe_parser;
pub mod pe_rebuilder;
pub mod shredder;
pub mod compliance;
pub mod simd;

pub use error::ShredderError;
pub use pe_parser::ParsedPE;
pub use pe_rebuilder::rebuild_pe;
pub use shredder::{shred, ShreddedCode, ShredderConfig};
pub use compliance::ComplianceManager;
pub use simd::{SIMDShredder, AVX2Shredder, AVX512Shredder, HIPAASecureShredder};
