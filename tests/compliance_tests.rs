//! Comprehensive Compliance Framework Tests
//! 
//! Unit tests verifying all compliance frameworks are properly implemented.

use shredder_rs::compliance::*;
use chrono::Utc;

#[test]
fn test_soc2_type1_compliance() {
    let mut compliance = SOC2Compliance::new();
    let result = compliance.validate_type1();
    assert!(result.is_ok(), "SOC2 Type I validation should pass");
    assert!(result.unwrap(), "SOC2 Type I should return true");
}

#[test]
fn test_soc2_type2_compliance() {
    let mut compliance = SOC2Compliance::new();
    compliance.record_audit();
    let result = compliance.validate_type2();
    assert!(result.is_ok(), "SOC2 Type II validation should pass after audit");
}

#[test]
fn test_iso27001_compliance() {
    let compliance = ISO27001Compliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "ISO27001 validation should pass");
}

#[test]
fn test_gdpr_compliance() {
    let compliance = GDPRCompliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "GDPR validation should pass");
}

#[test]
fn test_hipaa_compliance() {
    let compliance = HIPAACompliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "HIPAA validation should pass");
}

#[test]
fn test_hipaa_phi_access_logging() {
    let compliance = HIPAACompliance::new();
    let result = compliance.record_phi_access(
        "user123",
        "phi001",
        crate::compliance::hipaa::AccessAction::View,
        true,
        "Medical record review"
    );
    assert!(result.is_ok(), "PHI access should be logged");
}

#[test]
fn test_hipaa_encryption_verification() {
    let compliance = HIPAACompliance::new();
    let result = compliance.verify_encryption();
    assert!(result.is_ok(), "Encryption verification should pass");
}

#[test]
fn test_pci_dss_compliance() {
    let compliance = PCIDSSCompliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "PCI DSS validation should pass");
}

#[test]
fn test_nist_compliance() {
    let compliance = NISTCompliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "NIST validation should pass");
}

#[test]
fn test_osha_compliance() {
    let compliance = OSHACompliance::new();
    let result = compliance.validate();
    assert!(result.is_ok(), "OSHA validation should pass");
}

#[test]
fn test_compliance_manager_all_frameworks() {
    let mut manager = ComplianceManager::new();
    let result = manager.validate_all();
    assert!(result.is_ok(), "All compliance frameworks should validate");
    
    let status = result.unwrap();
    assert!(status.soc2_type1, "SOC2 Type I should be compliant");
    assert!(status.soc2_type2, "SOC2 Type II should be compliant");
    assert!(status.iso27001, "ISO27001 should be compliant");
    assert!(status.gdpr, "GDPR should be compliant");
    assert!(status.hipaa, "HIPAA should be compliant");
    assert!(status.pci_dss, "PCI DSS should be compliant");
    assert!(status.nist, "NIST should be compliant");
    assert!(status.osha, "OSHA should be compliant");
}

#[test]
fn test_audit_trail_logging() {
    use shredder_rs::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
    
    let mut trail = AuditTrail::new();
    trail.log(AuditEvent {
        timestamp: Utc::now(),
        level: AuditLevel::Info,
        category: "test".to_string(),
        message: "Test audit event".to_string(),
        user_id: Some("user123".to_string()),
        resource_id: None,
    });

    let events = trail.query(None, None, Some("test"), None, None);
    assert_eq!(events.len(), 1, "Should have one audit event");
}

#[test]
fn test_security_controls_management() {
    use shredder_rs::compliance::security_controls::{SecurityControls, SecurityControl, ControlType, ControlStatus};
    
    let controls = SecurityControls::new();
    
    let new_control = SecurityControl {
        id: "TEST-001".to_string(),
        name: "Test Control".to_string(),
        description: "Test description".to_string(),
        control_type: ControlType::Preventive,
        status: ControlStatus::Implemented,
        owner: "Test Owner".to_string(),
        implementation_date: Some(Utc::now()),
        last_tested: None,
        next_test: None,
        related_frameworks: vec!["SOC2".to_string()],
    };

    let result = controls.register_control(new_control);
    assert!(result.is_ok(), "Control registration should succeed");
}

#[test]
fn test_gdpr_data_subject_registration() {
    use shredder_rs::compliance::gdpr::DataSubject;
    
    let compliance = GDPRCompliance::new();
    let subject = DataSubject {
        id: "subject001".to_string(),
        name: Some("Test Subject".to_string()),
        email: Some("test@example.com".to_string()),
        data_categories: vec!["Personal Data".to_string()],
        processing_purposes: vec!["Service Delivery".to_string()],
        consent_given: true,
        consent_date: Some(Utc::now()),
        last_access: None,
    };

    let result = compliance.register_data_subject(subject);
    assert!(result.is_ok(), "Data subject registration should succeed");
}

#[test]
fn test_gdpr_consent_management() {
    use shredder_rs::compliance::gdpr::{ConsentRecord, ConsentMethod};
    
    let compliance = GDPRCompliance::new();
    let consent = ConsentRecord {
        subject_id: "subject001".to_string(),
        purpose: "Data Processing".to_string(),
        given: true,
        timestamp: Utc::now(),
        method: ConsentMethod::Explicit,
        withdrawal_date: None,
    };

    let result = compliance.record_consent(consent);
    assert!(result.is_ok(), "Consent recording should succeed");
}

#[test]
fn test_pci_dss_card_data_registration() {
    use shredder_rs::compliance::pci_dss::{CardDataRecord, RetentionPolicy};
    
    let compliance = PCIDSSCompliance::new();
    let card_data = CardDataRecord {
        id: "card001".to_string(),
        tokenized: true,
        encrypted: true,
        storage_location: "secure_vault".to_string(),
        access_log: vec![],
        retention_policy: RetentionPolicy {
            max_retention_days: 365,
            purpose: "Transaction processing".to_string(),
            legal_basis: "Contract".to_string(),
        },
    };

    let result = compliance.register_card_data(card_data);
    assert!(result.is_ok(), "Card data registration should succeed");
}

#[test]
fn test_osha_training_records() {
    use shredder_rs::compliance::osha::{TrainingRecord, TrainingType};
    
    let compliance = OSHACompliance::new();
    let training = TrainingRecord {
        id: "train001".to_string(),
        employee_id: "emp001".to_string(),
        training_type: TrainingType::ErgonomicSafety,
        completed: true,
        completion_date: Some(Utc::now()),
        expiration_date: Some(Utc::now() + chrono::Duration::days(365)),
        instructor: "Safety Officer".to_string(),
    };

    let result = compliance.record_training(training);
    assert!(result.is_ok(), "Training record should succeed");
}

#[test]
fn test_nist_function_state_update() {
    let compliance = NISTCompliance::new();
    let result = compliance.update_function_state(
        "ID.AM-1",
        crate::compliance::nist::ImplementationState::FullyImplemented
    );
    assert!(result.is_ok(), "Function state update should succeed");
}

#[test]
fn test_iso27001_risk_registration() {
    use shredder_rs::compliance::iso27001::{Risk, Likelihood, Impact, RiskLevel};
    
    let compliance = ISO27001Compliance::new();
    let risk = Risk {
        id: "risk001".to_string(),
        description: "Test risk".to_string(),
        likelihood: Likelihood::Possible,
        impact: Impact::Moderate,
        risk_level: RiskLevel::Medium,
        mitigation: "Test mitigation".to_string(),
        owner: "Risk Owner".to_string(),
        last_assessed: Utc::now(),
    };

    let result = compliance.register_risk(risk);
    assert!(result.is_ok(), "Risk registration should succeed");
}

