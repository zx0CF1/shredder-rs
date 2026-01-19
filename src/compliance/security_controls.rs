//! Security Controls Management System
//! 
//! Centralized management of security controls across all compliance frameworks.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct SecurityControls {
    audit_trail: Arc<Mutex<AuditTrail>>,
    controls: Arc<Mutex<HashMap<String, SecurityControl>>>,
    control_tests: Arc<Mutex<Vec<ControlTest>>>,
}

#[derive(Clone, Debug)]
pub struct SecurityControl {
    pub id: String,
    pub name: String,
    pub description: String,
    pub control_type: ControlType,
    pub status: ControlStatus,
    pub owner: String,
    pub implementation_date: Option<DateTime<Utc>>,
    pub last_tested: Option<DateTime<Utc>>,
    pub next_test: Option<DateTime<Utc>>,
    pub related_frameworks: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ControlType {
    Preventive,
    Detective,
    Corrective,
    Compensating,
    Physical,
    Technical,
    Administrative,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ControlStatus {
    Planned,
    Implemented,
    Operating,
    UnderReview,
    Deprecated,
}

#[derive(Clone, Debug)]
pub struct ControlTest {
    pub id: String,
    pub control_id: String,
    pub test_type: TestType,
    pub timestamp: DateTime<Utc>,
    pub tester: String,
    pub result: TestResult,
    pub findings: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestType {
    Automated,
    Manual,
    PenetrationTest,
    VulnerabilityScan,
    ComplianceAudit,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestResult {
    Pass,
    Fail,
    Partial,
    NotApplicable,
}

impl SecurityControls {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            controls: Arc::new(Mutex::new(Self::initialize_controls())),
            control_tests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn initialize_controls() -> HashMap<String, SecurityControl> {
        let mut controls = HashMap::new();

        // Access Control
        controls.insert("ACC-001".to_string(), SecurityControl {
            id: "ACC-001".to_string(),
            name: "Multi-Factor Authentication".to_string(),
            description: "Require MFA for all privileged access".to_string(),
            control_type: ControlType::Preventive,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(90)),
            related_frameworks: vec!["SOC2".to_string(), "ISO27001".to_string(), "NIST".to_string()],
        });

        // Encryption
        controls.insert("ENC-001".to_string(), SecurityControl {
            id: "ENC-001".to_string(),
            name: "Data Encryption at Rest".to_string(),
            description: "Encrypt all sensitive data at rest using AES-256".to_string(),
            control_type: ControlType::Preventive,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(90)),
            related_frameworks: vec!["HIPAA".to_string(), "PCI DSS".to_string(), "ISO27001".to_string()],
        });

        controls.insert("ENC-002".to_string(), SecurityControl {
            id: "ENC-002".to_string(),
            name: "Data Encryption in Transit".to_string(),
            description: "Encrypt all data in transit using TLS 1.3".to_string(),
            control_type: ControlType::Preventive,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(90)),
            related_frameworks: vec!["HIPAA".to_string(), "PCI DSS".to_string(), "ISO27001".to_string()],
        });

        // Monitoring
        controls.insert("MON-001".to_string(), SecurityControl {
            id: "MON-001".to_string(),
            name: "Security Event Monitoring".to_string(),
            description: "Monitor and log all security events".to_string(),
            control_type: ControlType::Detective,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(90)),
            related_frameworks: vec!["SOC2".to_string(), "ISO27001".to_string(), "NIST".to_string()],
        });

        // Incident Response
        controls.insert("IR-001".to_string(), SecurityControl {
            id: "IR-001".to_string(),
            name: "Incident Response Plan".to_string(),
            description: "Documented and tested incident response procedures".to_string(),
            control_type: ControlType::Corrective,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(180)),
            related_frameworks: vec!["ISO27001".to_string(), "NIST".to_string()],
        });

        // Vulnerability Management
        controls.insert("VULN-001".to_string(), SecurityControl {
            id: "VULN-001".to_string(),
            name: "Vulnerability Scanning".to_string(),
            description: "Regular vulnerability scans and remediation".to_string(),
            control_type: ControlType::Detective,
            status: ControlStatus::Operating,
            owner: "Security Team".to_string(),
            implementation_date: Some(Utc::now()),
            last_tested: Some(Utc::now()),
            next_test: Some(Utc::now() + chrono::Duration::days(90)),
            related_frameworks: vec!["PCI DSS".to_string(), "ISO27001".to_string()],
        });

        controls
    }

    pub fn register_control(&self, control: SecurityControl) -> Result<(), String> {
        let mut controls = self.controls.lock().unwrap();
        controls.insert(control.id.clone(), control.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "security_control".to_string(),
            message: format!("Security control registered: {}", control.id),
            user_id: None,
            resource_id: Some(control.id.clone()),
        });

        Ok(())
    }

    pub fn test_control(&self, test: ControlTest) -> Result<(), String> {
        let mut tests = self.control_tests.lock().unwrap();
        tests.push(test.clone());

        // Update control last tested date
        let mut controls = self.controls.lock().unwrap();
        if let Some(control) = controls.get_mut(&test.control_id) {
            control.last_tested = Some(test.timestamp);
            control.next_test = Some(test.timestamp + chrono::Duration::days(90));

            if test.result == TestResult::Fail {
                control.status = ControlStatus::UnderReview;
            }
        }

        let level = match test.result {
            TestResult::Pass => AuditLevel::Info,
            TestResult::Fail => AuditLevel::Error,
            TestResult::Partial => AuditLevel::Warning,
            _ => AuditLevel::Info,
        };

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level,
            category: "security_control_test".to_string(),
            message: format!("Control test {} completed: {:?}", test.control_id, test.result),
            user_id: Some(test.tester.clone()),
            resource_id: Some(test.control_id.clone()),
        });

        Ok(())
    }

    pub fn get_controls_by_framework(&self, framework: &str) -> Vec<SecurityControl> {
        let controls = self.controls.lock().unwrap();
        controls.values()
            .filter(|c| c.related_frameworks.contains(&framework.to_string()))
            .cloned()
            .collect()
    }

    pub fn get_overdue_tests(&self) -> Vec<SecurityControl> {
        let controls = self.controls.lock().unwrap();
        controls.values()
            .filter(|c| {
                if let Some(next_test) = c.next_test {
                    next_test < Utc::now()
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }
}

impl Default for SecurityControls {
    fn default() -> Self {
        Self::new()
    }
}

