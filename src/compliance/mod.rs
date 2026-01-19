//! Comprehensive Compliance and Regulatory Framework
//! 
//! This module provides enterprise-grade compliance monitoring and enforcement
//! for security-critical environments including healthcare, finance, and government.

pub mod soc2;
pub mod iso27001;
pub mod gdpr;
pub mod hipaa;
pub mod pci_dss;
pub mod nist;
pub mod osha;
pub mod audit;
pub mod security_controls;

pub use soc2::SOC2Compliance;
pub use iso27001::ISO27001Compliance;
pub use gdpr::GDPRCompliance;
pub use hipaa::HIPAACompliance;
pub use pci_dss::PCIDSSCompliance;
pub use nist::NISTCompliance;
pub use osha::OSHACompliance;
pub use audit::{AuditTrail, AuditEvent, AuditLevel};
pub use security_controls::SecurityControls;

/// Central compliance manager coordinating all frameworks
pub struct ComplianceManager {
    pub soc2: SOC2Compliance,
    pub iso27001: ISO27001Compliance,
    pub gdpr: GDPRCompliance,
    pub hipaa: HIPAACompliance,
    pub pci_dss: PCIDSSCompliance,
    pub nist: NISTCompliance,
    pub osha: OSHACompliance,
    pub audit_trail: AuditTrail,
    pub security_controls: SecurityControls,
}

impl ComplianceManager {
    pub fn new() -> Self {
        Self {
            soc2: SOC2Compliance::new(),
            iso27001: ISO27001Compliance::new(),
            gdpr: GDPRCompliance::new(),
            hipaa: HIPAACompliance::new(),
            pci_dss: PCIDSSCompliance::new(),
            nist: NISTCompliance::new(),
            osha: OSHACompliance::new(),
            audit_trail: AuditTrail::new(),
            security_controls: SecurityControls::new(),
        }
    }

    /// Validates all compliance frameworks before mutation operations
    pub fn validate_all(&mut self) -> Result<ComplianceStatus, ComplianceError> {
        let mut status = ComplianceStatus::default();
        
        status.soc2_type1 = self.soc2.validate_type1().map_err(ComplianceError::SOC2Type1)?;
        status.soc2_type2 = self.soc2.validate_type2().map_err(ComplianceError::SOC2Type2)?;
        status.iso27001 = self.iso27001.validate().map_err(ComplianceError::ISO27001)?;
        status.gdpr = self.gdpr.validate().map_err(ComplianceError::GDPR)?;
        status.hipaa = self.hipaa.validate().map_err(ComplianceError::HIPAA)?;
        status.pci_dss = self.pci_dss.validate().map_err(ComplianceError::PCIDSS)?;
        status.nist = self.nist.validate().map_err(ComplianceError::NIST)?;
        status.osha = self.osha.validate().map_err(ComplianceError::OSHA)?;
        
        self.audit_trail.log(AuditEvent {
            timestamp: chrono::Utc::now(),
            level: AuditLevel::Info,
            category: "compliance".to_string(),
            message: "Full compliance validation completed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(status)
    }
}

#[derive(Debug, Default)]
pub struct ComplianceStatus {
    pub soc2_type1: bool,
    pub soc2_type2: bool,
    pub iso27001: bool,
    pub gdpr: bool,
    pub hipaa: bool,
    pub pci_dss: bool,
    pub nist: bool,
    pub osha: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    #[error("SOC2 Type I validation failed: {0}")]
    SOC2Type1(String),
    #[error("SOC2 Type II validation failed: {0}")]
    SOC2Type2(String),
    #[error("ISO27001 validation failed: {0}")]
    ISO27001(String),
    #[error("GDPR validation failed: {0}")]
    GDPR(String),
    #[error("HIPAA validation failed: {0}")]
    HIPAA(String),
    #[error("PCI DSS validation failed: {0}")]
    PCIDSS(String),
    #[error("NIST validation failed: {0}")]
    NIST(String),
    #[error("OSHA validation failed: {0}")]
    OSHA(String),
    #[error("Audit trail error: {0}")]
    Audit(String),
}

