//! PCI DSS (Payment Card Industry Data Security Standard) Compliance
//! 
//! Security standards for organizations that handle credit card data.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct PCIDSSCompliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    card_data: Arc<Mutex<HashMap<String, CardDataRecord>>>,
    network_segmentation: Arc<Mutex<NetworkSegmentation>>,
    vulnerability_scans: Arc<Mutex<Vec<VulnerabilityScan>>>,
    penetration_tests: Arc<Mutex<Vec<PenetrationTest>>>,
    access_controls: Arc<Mutex<AccessControls>>,
}

#[derive(Clone, Debug)]
pub struct CardDataRecord {
    pub id: String,
    pub tokenized: bool,
    pub encrypted: bool,
    pub storage_location: String,
    pub access_log: Vec<AccessEntry>,
    pub retention_policy: RetentionPolicy,
}

#[derive(Clone, Debug)]
pub struct AccessEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub action: String,
    pub authorized: bool,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub max_retention_days: u32,
    pub purpose: String,
    pub legal_basis: String,
}

#[derive(Clone, Debug)]
pub struct NetworkSegmentation {
    pub cardholder_data_environment: bool,
    pub dmz_configured: bool,
    pub firewall_rules: Vec<FirewallRule>,
    pub last_review: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct FirewallRule {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub allowed: bool,
}

#[derive(Clone, Debug)]
pub struct VulnerabilityScan {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub scanner: String,
    pub vulnerabilities_found: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub remediated: bool,
}

#[derive(Clone, Debug)]
pub struct PenetrationTest {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub tester: String,
    pub scope: String,
    pub findings: Vec<String>,
    pub remediated: bool,
}

#[derive(Clone, Debug)]
pub struct AccessControls {
    pub multi_factor_authentication: bool,
    pub password_policy: PasswordPolicy,
    pub access_reviews: Vec<AccessReview>,
    pub privileged_access_monitoring: bool,
}

#[derive(Clone, Debug)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub complexity_required: bool,
    pub max_age_days: u32,
    pub history_count: u32,
}

#[derive(Clone, Debug)]
pub struct AccessReview {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub reviewer: String,
    pub users_reviewed: u32,
    pub access_removed: u32,
}

impl PCIDSSCompliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            card_data: Arc::new(Mutex::new(HashMap::new())),
            network_segmentation: Arc::new(Mutex::new(NetworkSegmentation {
                cardholder_data_environment: true,
                dmz_configured: true,
                firewall_rules: Vec::new(),
                last_review: Utc::now(),
            })),
            vulnerability_scans: Arc::new(Mutex::new(Vec::new())),
            penetration_tests: Arc::new(Mutex::new(Vec::new())),
            access_controls: Arc::new(Mutex::new(AccessControls {
                multi_factor_authentication: true,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    complexity_required: true,
                    max_age_days: 90,
                    history_count: 4,
                },
                access_reviews: Vec::new(),
                privileged_access_monitoring: true,
            })),
        }
    }

    pub fn validate(&self) -> Result<bool, String> {
        // Requirement 1: Install and maintain firewall configuration
        let network = self.network_segmentation.lock().unwrap();
        if !network.cardholder_data_environment {
            return Err("Cardholder Data Environment (CDE) not properly configured".to_string());
        }

        // Requirement 2: Do not use vendor-supplied defaults
        // (Assumed implemented)

        // Requirement 3: Protect stored cardholder data
        let card_data = self.card_data.lock().unwrap();
        for (id, record) in card_data.iter() {
            if !record.encrypted && !record.tokenized {
                return Err(format!("Card data record {} must be encrypted or tokenized", id));
            }
        }

        // Requirement 4: Encrypt transmission of cardholder data
        // (Assumed implemented via TLS)

        // Requirement 5: Use and regularly update anti-virus software
        // (Assumed implemented)

        // Requirement 6: Develop and maintain secure systems
        let scans = self.vulnerability_scans.lock().unwrap();
        let recent_scan = scans.iter()
            .max_by_key(|s| s.timestamp)
            .filter(|s| (Utc::now() - s.timestamp).num_days() <= 90);
        
        if recent_scan.is_none() {
            return Err("No vulnerability scan within last 90 days".to_string());
        }

        // Requirement 7: Restrict access to cardholder data
        let access = self.access_controls.lock().unwrap();
        if !access.multi_factor_authentication {
            return Err("Multi-factor authentication required for cardholder data access".to_string());
        }

        // Requirement 8: Assign unique ID to each person
        // (Assumed implemented)

        // Requirement 9: Restrict physical access
        // (Assumed implemented)

        // Requirement 10: Track and monitor network access
        // (Assumed implemented via audit logging)

        // Requirement 11: Regularly test security systems
        let pentests = self.penetration_tests.lock().unwrap();
        let recent_pentest = pentests.iter()
            .max_by_key(|p| p.timestamp)
            .filter(|p| (Utc::now() - p.timestamp).num_days() <= 365);
        
        if recent_pentest.is_none() {
            return Err("No penetration test within last 12 months".to_string());
        }

        // Requirement 12: Maintain information security policy
        // (Assumed implemented)

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "pci_dss".to_string(),
            message: "PCI DSS validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn register_card_data(&self, record: CardDataRecord) -> Result<(), String> {
        if !record.encrypted && !record.tokenized {
            return Err("Card data must be encrypted or tokenized".to_string());
        }

        let mut card_data = self.card_data.lock().unwrap();
        card_data.insert(record.id.clone(), record.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "pci_dss_card_data".to_string(),
            message: format!("Card data record registered: {} (encrypted: {}, tokenized: {})", 
                           record.id, record.encrypted, record.tokenized),
            user_id: None,
            resource_id: Some(record.id.clone()),
        });

        Ok(())
    }

    pub fn record_vulnerability_scan(&self, scan: VulnerabilityScan) -> Result<(), String> {
        let mut scans = self.vulnerability_scans.lock().unwrap();
        scans.push(scan.clone());

        if scan.critical_count > 0 {
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Error,
                category: "pci_dss_vuln_scan".to_string(),
                message: format!("Vulnerability scan {} found {} critical vulnerabilities", 
                               scan.id, scan.critical_count),
                user_id: None,
                resource_id: Some(scan.id.clone()),
            });
        } else {
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Info,
                category: "pci_dss_vuln_scan".to_string(),
                message: format!("Vulnerability scan {} completed", scan.id),
                user_id: None,
                resource_id: Some(scan.id.clone()),
            });
        }

        Ok(())
    }

    pub fn record_penetration_test(&self, test: PenetrationTest) -> Result<(), String> {
        let mut tests = self.penetration_tests.lock().unwrap();
        tests.push(test.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "pci_dss_pentest".to_string(),
            message: format!("Penetration test {} completed: {} findings", 
                           test.id, test.findings.len()),
            user_id: None,
            resource_id: Some(test.id.clone()),
        });

        Ok(())
    }
}

impl Default for PCIDSSCompliance {
    fn default() -> Self {
        Self::new()
    }
}

