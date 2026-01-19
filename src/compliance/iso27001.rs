//! ISO/IEC 27001 Information Security Management System
//! 
//! International standard for information security management systems.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct ISO27001Compliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    controls: Arc<Mutex<HashMap<String, ISOControl>>>,
    risk_register: Arc<Mutex<Vec<Risk>>>,
    last_review: Arc<Mutex<Option<DateTime<Utc>>>>,
}

#[derive(Clone, Debug)]
pub struct ISOControl {
    pub id: String,
    pub name: String,
    pub category: ControlCategory,
    pub status: ControlStatus,
    pub implementation_date: Option<DateTime<Utc>>,
    pub last_review: DateTime<Utc>,
    pub owner: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ControlCategory {
    Organizational,
    People,
    Physical,
    Technological,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ControlStatus {
    Implemented,
    PartiallyImplemented,
    NotImplemented,
    UnderReview,
}

#[derive(Clone, Debug)]
pub struct Risk {
    pub id: String,
    pub description: String,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub risk_level: RiskLevel,
    pub mitigation: String,
    pub owner: String,
    pub last_assessed: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Likelihood {
    Rare,
    Unlikely,
    Possible,
    Likely,
    AlmostCertain,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Impact {
    Negligible,
    Minor,
    Moderate,
    Major,
    Catastrophic,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ISO27001Compliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            controls: Arc::new(Mutex::new(Self::initialize_controls())),
            risk_register: Arc::new(Mutex::new(Vec::new())),
            last_review: Arc::new(Mutex::new(None)),
        }
    }

    fn initialize_controls() -> HashMap<String, ISOControl> {
        let mut controls = HashMap::new();

        // A.5 Information Security Policies
        controls.insert("A.5.1.1".to_string(), ISOControl {
            id: "A.5.1.1".to_string(),
            name: "Policies for Information Security".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Security Team".to_string(),
        });

        // A.6 Organization of Information Security
        controls.insert("A.6.1.1".to_string(), ISOControl {
            id: "A.6.1.1".to_string(),
            name: "Information Security Roles and Responsibilities".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Security Team".to_string(),
        });

        // A.7 Human Resource Security
        controls.insert("A.7.1.1".to_string(), ISOControl {
            id: "A.7.1.1".to_string(),
            name: "Screening".to_string(),
            category: ControlCategory::People,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "HR Team".to_string(),
        });

        // A.8 Asset Management
        controls.insert("A.8.1.1".to_string(), ISOControl {
            id: "A.8.1.1".to_string(),
            name: "Inventory of Assets".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "IT Team".to_string(),
        });

        // A.9 Access Control
        controls.insert("A.9.1.1".to_string(), ISOControl {
            id: "A.9.1.1".to_string(),
            name: "Access Control Policy".to_string(),
            category: ControlCategory::Technological,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Security Team".to_string(),
        });

        // A.10 Cryptography
        controls.insert("A.10.1.1".to_string(), ISOControl {
            id: "A.10.1.1".to_string(),
            name: "Cryptographic Controls".to_string(),
            category: ControlCategory::Technological,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Security Team".to_string(),
        });

        // A.11 Physical and Environmental Security
        controls.insert("A.11.1.1".to_string(), ISOControl {
            id: "A.11.1.1".to_string(),
            name: "Physical Security Perimeters".to_string(),
            category: ControlCategory::Physical,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Facilities Team".to_string(),
        });

        // A.12 Operations Security
        controls.insert("A.12.1.1".to_string(), ISOControl {
            id: "A.12.1.1".to_string(),
            name: "Documented Operating Procedures".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Operations Team".to_string(),
        });

        // A.13 Communications Security
        controls.insert("A.13.1.1".to_string(), ISOControl {
            id: "A.13.1.1".to_string(),
            name: "Network Controls".to_string(),
            category: ControlCategory::Technological,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Network Team".to_string(),
        });

        // A.14 System Acquisition, Development and Maintenance
        controls.insert("A.14.1.1".to_string(), ISOControl {
            id: "A.14.1.1".to_string(),
            name: "Information Security Requirements".to_string(),
            category: ControlCategory::Technological,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Development Team".to_string(),
        });

        // A.15 Supplier Relationships
        controls.insert("A.15.1.1".to_string(), ISOControl {
            id: "A.15.1.1".to_string(),
            name: "Information Security in Supplier Relationships".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Procurement Team".to_string(),
        });

        // A.16 Information Security Incident Management
        controls.insert("A.16.1.1".to_string(), ISOControl {
            id: "A.16.1.1".to_string(),
            name: "Management of Information Security Incidents".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Security Team".to_string(),
        });

        // A.17 Information Security Aspects of Business Continuity Management
        controls.insert("A.17.1.1".to_string(), ISOControl {
            id: "A.17.1.1".to_string(),
            name: "Planning Information Security Continuity".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Business Continuity Team".to_string(),
        });

        // A.18 Compliance
        controls.insert("A.18.1.1".to_string(), ISOControl {
            id: "A.18.1.1".to_string(),
            name: "Identification of Applicable Legislation".to_string(),
            category: ControlCategory::Organizational,
            status: ControlStatus::Implemented,
            implementation_date: Some(Utc::now()),
            last_review: Utc::now(),
            owner: "Legal Team".to_string(),
        });

        controls
    }

    pub fn validate(&self) -> Result<bool, String> {
        let controls = self.controls.lock().unwrap();
        let mut all_implemented = true;
        let mut failures = Vec::new();

        for (id, control) in controls.iter() {
            if control.status != ControlStatus::Implemented {
                all_implemented = false;
                failures.push(format!("{}: {}", id, control.name));
            }

            // Check if control was reviewed within last year
            let days_since_review = (Utc::now() - control.last_review).num_days();
            if days_since_review > 365 {
                all_implemented = false;
                failures.push(format!("{}: Review overdue ({} days)", id, days_since_review));
            }
        }

        // Check risk register
        let risks = self.risk_register.lock().unwrap();
        let critical_risks = risks.iter()
            .filter(|r| r.risk_level == RiskLevel::Critical)
            .count();
        
        if critical_risks > 0 {
            return Err(format!("ISO27001 validation failed: {} critical risks require mitigation", critical_risks));
        }

        if !all_implemented {
            return Err(format!("ISO27001 validation failed. Controls not implemented: {:?}", failures));
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "iso27001".to_string(),
            message: "ISO27001 validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn register_risk(&self, risk: Risk) -> Result<(), String> {
        let mut risks = self.risk_register.lock().unwrap();
        risks.push(risk.clone());
        
        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Warning,
            category: "iso27001_risk".to_string(),
            message: format!("Risk registered: {} - {}", risk.id, risk.description),
            user_id: None,
            resource_id: Some(risk.id.clone()),
        });

        Ok(())
    }

    pub fn update_control_status(&self, id: &str, status: ControlStatus) -> Result<(), String> {
        let mut controls = self.controls.lock().unwrap();
        if let Some(control) = controls.get_mut(id) {
            control.status = status;
            control.last_review = Utc::now();
            
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Info,
                category: "iso27001_control".to_string(),
                message: format!("Control {} status updated to {:?}", id, status),
                user_id: None,
                resource_id: Some(id.to_string()),
            });
            
            Ok(())
        } else {
            Err(format!("Control {} not found", id))
        }
    }
}

impl Default for ISO27001Compliance {
    fn default() -> Self {
        Self::new()
    }
}

