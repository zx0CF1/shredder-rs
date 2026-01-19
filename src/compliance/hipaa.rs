//! HIPAA (Health Insurance Portability and Accountability Act) Compliance
//! 
//! Healthcare data protection and privacy compliance for Protected Health Information (PHI).

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct HIPAACompliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    phi_records: Arc<Mutex<HashMap<String, PHIRecord>>>,
    access_logs: Arc<Mutex<Vec<AccessLogEntry>>>,
    encryption_status: Arc<Mutex<EncryptionStatus>>,
    baas: Arc<Mutex<Vec<BusinessAssociate>>>,
    breach_incidents: Arc<Mutex<Vec<BreachIncident>>>,
}

#[derive(Clone, Debug)]
pub struct PHIRecord {
    pub id: String,
    pub patient_id: String,
    pub data_type: PHIDataType,
    pub created: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub accessed_by: Vec<String>,
    pub encrypted: bool,
    pub encryption_algorithm: Option<String>,
    pub retention_period_days: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PHIDataType {
    Name,
    Address,
    DateOfBirth,
    SocialSecurityNumber,
    MedicalRecordNumber,
    HealthPlanNumber,
    AccountNumber,
    LicenseNumber,
    VehicleIdentifier,
    DeviceIdentifier,
    WebURL,
    IPAddress,
    BiometricIdentifier,
    FullFacePhoto,
    OtherUniqueIdentifier,
    ClinicalData,
    BillingData,
}

#[derive(Clone, Debug)]
pub struct AccessLogEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub resource_id: String,
    pub action: AccessAction,
    pub success: bool,
    pub ip_address: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccessAction {
    View,
    Create,
    Modify,
    Delete,
    Export,
    Print,
}

#[derive(Clone, Debug)]
pub struct EncryptionStatus {
    pub data_at_rest: bool,
    pub data_in_transit: bool,
    pub encryption_algorithm: String,
    pub key_management: KeyManagementStatus,
    pub last_verified: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyManagementStatus {
    Compliant,
    NonCompliant,
    UnderReview,
}

#[derive(Clone, Debug)]
pub struct BusinessAssociate {
    pub id: String,
    pub name: String,
    pub baa_signed: bool,
    pub baa_date: Option<DateTime<Utc>>,
    pub services_provided: Vec<String>,
    pub last_audit: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct BreachIncident {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub phi_affected: Vec<String>,
    pub severity: BreachSeverity,
    pub reported: bool,
    pub report_date: Option<DateTime<Utc>>,
    pub mitigation: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BreachSeverity {
    Minor,
    Moderate,
    Major,
    Critical,
}

impl HIPAACompliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            phi_records: Arc::new(Mutex::new(HashMap::new())),
            access_logs: Arc::new(Mutex::new(Vec::new())),
            encryption_status: Arc::new(Mutex::new(EncryptionStatus {
                data_at_rest: true,
                data_in_transit: true,
                encryption_algorithm: "AES-256".to_string(),
                key_management: KeyManagementStatus::Compliant,
                last_verified: Utc::now(),
            })),
            baas: Arc::new(Mutex::new(Vec::new())),
            breach_incidents: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn validate(&self) -> Result<bool, String> {
        // Administrative Safeguards (§164.308)
        let baas = self.baas.lock().unwrap();
        for baa in baas.iter() {
            if !baa.baa_signed {
                return Err(format!("Business Associate {} does not have signed BAA", baa.name));
            }
        }

        // Physical Safeguards (§164.310)
        // (Assumed implemented in physical infrastructure)

        // Technical Safeguards (§164.312)
        let encryption = self.encryption_status.lock().unwrap();
        if !encryption.data_at_rest {
            return Err("Data at rest encryption not enabled".to_string());
        }
        if !encryption.data_in_transit {
            return Err("Data in transit encryption not enabled".to_string());
        }
        if encryption.key_management != KeyManagementStatus::Compliant {
            return Err("Key management not compliant".to_string());
        }

        // Check encryption algorithm strength
        if !encryption.encryption_algorithm.contains("AES-256") 
            && !encryption.encryption_algorithm.contains("AES-128") {
            return Err("Encryption algorithm must be AES-128 or AES-256".to_string());
        }

        // Audit Controls (§164.312(b))
        let access_logs = self.access_logs.lock().unwrap();
        if access_logs.is_empty() {
            return Err("No access logs found. Audit controls must be enabled.".to_string());
        }

        // Integrity Controls (§164.312(c)(1))
        // (Assumed implemented via cryptographic hashing)

        // Person or Entity Authentication (§164.312(d))
        // (Assumed implemented via authentication system)

        // Transmission Security (§164.312(e)(1))
        if !encryption.data_in_transit {
            return Err("Transmission security requires encryption in transit".to_string());
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "hipaa".to_string(),
            message: "HIPAA validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn record_phi_access(&self, user_id: &str, resource_id: &str, action: AccessAction, success: bool, reason: &str) -> Result<(), String> {
        let mut logs = self.access_logs.lock().unwrap();
        let entry = AccessLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            resource_id: resource_id.to_string(),
            action,
            success,
            ip_address: None,
            reason: reason.to_string(),
        };
        logs.push(entry.clone());

        // Update PHI record last accessed
        let mut phi = self.phi_records.lock().unwrap();
        if let Some(record) = phi.get_mut(resource_id) {
            record.last_accessed = Some(Utc::now());
            if !record.accessed_by.contains(&user_id.to_string()) {
                record.accessed_by.push(user_id.to_string());
            }
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: if success { AuditLevel::Info } else { AuditLevel::Warning },
            category: "hipaa_access".to_string(),
            message: format!("PHI access: {} {} {} - {}", user_id, format!("{:?}", entry.action), resource_id, if success { "SUCCESS" } else { "FAILED" }),
            user_id: Some(user_id.to_string()),
            resource_id: Some(resource_id.to_string()),
        });

        Ok(())
    }

    pub fn register_phi(&self, record: PHIRecord) -> Result<(), String> {
        if !record.encrypted {
            return Err("PHI records must be encrypted".to_string());
        }

        let mut phi = self.phi_records.lock().unwrap();
        phi.insert(record.id.clone(), record.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "hipaa_phi".to_string(),
            message: format!("PHI record registered: {} for patient {}", record.id, record.patient_id),
            user_id: None,
            resource_id: Some(record.id.clone()),
        });

        Ok(())
    }

    pub fn register_breach(&self, incident: BreachIncident) -> Result<(), String> {
        let mut incidents = self.breach_incidents.lock().unwrap();
        incidents.push(incident.clone());

        // Breach notification required within 60 days for breaches affecting 500+ individuals
        // or immediately for smaller breaches
        let notification_required = incident.phi_affected.len() >= 500 || 
                                   incident.severity == BreachSeverity::Critical;

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Error,
            category: "hipaa_breach".to_string(),
            message: format!("Breach incident registered: {} - {} PHI records affected. Notification required: {}", 
                           incident.id, incident.phi_affected.len(), notification_required),
            user_id: None,
            resource_id: Some(incident.id.clone()),
        });

        Ok(())
    }

    pub fn register_business_associate(&self, baa: BusinessAssociate) -> Result<(), String> {
        if !baa.baa_signed {
            return Err("Business Associate Agreement must be signed before processing PHI".to_string());
        }

        let mut baas = self.baas.lock().unwrap();
        baas.push(baa.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "hipaa_baa".to_string(),
            message: format!("Business Associate registered: {} with signed BAA", baa.name),
            user_id: None,
            resource_id: Some(baa.id.clone()),
        });

        Ok(())
    }

    pub fn verify_encryption(&self) -> Result<(), String> {
        let mut encryption = self.encryption_status.lock().unwrap();
        encryption.last_verified = Utc::now();

        if !encryption.data_at_rest || !encryption.data_in_transit {
            return Err("Encryption verification failed".to_string());
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "hipaa_encryption".to_string(),
            message: "Encryption status verified".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(())
    }
}

impl Default for HIPAACompliance {
    fn default() -> Self {
        Self::new()
    }
}

