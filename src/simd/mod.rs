//! SIMD, AVX2, and AVX512 Instruction Support with HIPAA Compliance
//! 
//! Advanced vector instruction support for high-performance mutation operations
//! with full HIPAA compliance for healthcare environments.

pub mod avx2;
pub mod avx512;
pub mod simd;
pub mod hipaa_secure;

pub use avx2::AVX2Shredder;
pub use avx512::AVX512Shredder;
pub use simd::SIMDShredder;
pub use hipaa_secure::HIPAASecureShredder;

