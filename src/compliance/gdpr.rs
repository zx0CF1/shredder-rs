//! GDPR (General Data Protection Regulation) Compliance
//! 
//! European Union data protection and privacy regulation compliance.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct GDPRCompliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    data_subjects: Arc<Mutex<HashMap<String, DataSubject>>>,
    processing_activities: Arc<Mutex<Vec<ProcessingActivity>>>,
    consent_records: Arc<Mutex<HashMap<String, ConsentRecord>>>,
    data_retention_policies: Arc<Mutex<Vec<RetentionPolicy>>>,
}

#[derive(Clone, Debug)]
pub struct DataSubject {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub data_categories: Vec<String>,
    pub processing_purposes: Vec<String>,
    pub consent_given: bool,
    pub consent_date: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct ProcessingActivity {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<String>,
    pub recipients: Vec<String>,
    pub retention_period_days: u32,
    pub security_measures: Vec<String>,
    pub created: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

#[derive(Clone, Debug)]
pub struct ConsentRecord {
    pub subject_id: String,
    pub purpose: String,
    pub given: bool,
    pub timestamp: DateTime<Utc>,
    pub method: ConsentMethod,
    pub withdrawal_date: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConsentMethod {
    Explicit,
    Implicit,
    OptIn,
    OptOut,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub data_category: String,
    pub retention_period_days: u32,
    pub legal_basis: String,
    pub deletion_procedure: String,
}

impl GDPRCompliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            data_subjects: Arc::new(Mutex::new(HashMap::new())),
            processing_activities: Arc::new(Mutex::new(Vec::new())),
            consent_records: Arc::new(Mutex::new(HashMap::new())),
            data_retention_policies: Arc::new(Mutex::new(Self::default_retention_policies())),
        }
    }

    fn default_retention_policies() -> Vec<RetentionPolicy> {
        vec![
            RetentionPolicy {
                data_category: "Personal Identifiable Information".to_string(),
                retention_period_days: 2555, // 7 years
                legal_basis: "Legal obligation".to_string(),
                deletion_procedure: "Secure deletion with cryptographic erasure".to_string(),
            },
            RetentionPolicy {
                data_category: "Health Data".to_string(),
                retention_period_days: 3650, // 10 years
                legal_basis: "Legal obligation".to_string(),
                deletion_procedure: "HIPAA-compliant secure deletion".to_string(),
            },
            RetentionPolicy {
                data_category: "Financial Data".to_string(),
                retention_period_days: 2555, // 7 years
                legal_basis: "Legal obligation".to_string(),
                deletion_procedure: "PCI DSS compliant secure deletion".to_string(),
            },
        ]
    }

    pub fn validate(&self) -> Result<bool, String> {
        // Article 5: Principles of processing
        let subjects = self.data_subjects.lock().unwrap();
        let activities = self.processing_activities.lock().unwrap();
        let consents = self.consent_records.lock().unwrap();

        // Check that all processing activities have legal basis
        for activity in activities.iter() {
            if activity.legal_basis == LegalBasis::Consent {
                // Verify consent exists
                let consent_key = format!("{}:{}", activity.id, activity.purpose);
                if !consents.contains_key(&consent_key) {
                    return Err(format!("Processing activity {} requires consent but none found", activity.id));
                }
            }
        }

        // Check data minimization (Article 5(1)(c))
        for subject in subjects.values() {
            if subject.data_categories.is_empty() {
                return Err(format!("Data subject {} has no data categories defined", subject.id));
            }
        }

        // Check purpose limitation (Article 5(1)(b))
        for activity in activities.iter() {
            if activity.purpose.is_empty() {
                return Err(format!("Processing activity {} has no purpose defined", activity.id));
            }
        }

        // Check storage limitation (Article 5(1)(e))
        let policies = self.data_retention_policies.lock().unwrap();
        if policies.is_empty() {
            return Err("No data retention policies defined".to_string());
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "gdpr".to_string(),
            message: "GDPR validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn register_data_subject(&self, subject: DataSubject) -> Result<(), String> {
        let mut subjects = self.data_subjects.lock().unwrap();
        subjects.insert(subject.id.clone(), subject.clone());
        
        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "gdpr_subject".to_string(),
            message: format!("Data subject registered: {}", subject.id),
            user_id: None,
            resource_id: Some(subject.id.clone()),
        });

        Ok(())
    }

    pub fn record_consent(&self, consent: ConsentRecord) -> Result<(), String> {
        let mut consents = self.consent_records.lock().unwrap();
        let key = format!("{}:{}", consent.subject_id, consent.purpose);
        consents.insert(key.clone(), consent.clone());
        
        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "gdpr_consent".to_string(),
            message: format!("Consent recorded for subject {}: {}", consent.subject_id, consent.purpose),
            user_id: None,
            resource_id: Some(key),
        });

        Ok(())
    }

    pub fn withdraw_consent(&self, subject_id: &str, purpose: &str) -> Result<(), String> {
        let mut consents = self.consent_records.lock().unwrap();
        let key = format!("{}:{}", subject_id, purpose);
        
        if let Some(consent) = consents.get_mut(&key) {
            consent.given = false;
            consent.withdrawal_date = Some(Utc::now());
            
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Warning,
                category: "gdpr_consent_withdrawal".to_string(),
                message: format!("Consent withdrawn for subject {}: {}", subject_id, purpose),
                user_id: None,
                resource_id: Some(key),
            });
            
            Ok(())
        } else {
            Err(format!("Consent record not found for subject {} and purpose {}", subject_id, purpose))
        }
    }

    pub fn register_processing_activity(&self, activity: ProcessingActivity) -> Result<(), String> {
        let mut activities = self.processing_activities.lock().unwrap();
        activities.push(activity.clone());
        
        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "gdpr_processing".to_string(),
            message: format!("Processing activity registered: {}", activity.id),
            user_id: None,
            resource_id: Some(activity.id.clone()),
        });

        Ok(())
    }

    pub fn request_data_erasure(&self, subject_id: &str) -> Result<(), String> {
        let mut subjects = self.data_subjects.lock().unwrap();
        if subjects.remove(subject_id).is_some() {
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Warning,
                category: "gdpr_erasure".to_string(),
                message: format!("Right to erasure exercised by subject: {}", subject_id),
                user_id: None,
                resource_id: Some(subject_id.to_string()),
            });
            Ok(())
        } else {
            Err(format!("Data subject {} not found", subject_id))
        }
    }

    pub fn request_data_portability(&self, subject_id: &str) -> Result<Vec<u8>, String> {
        let subjects = self.data_subjects.lock().unwrap();
        if let Some(subject) = subjects.get(subject_id) {
            // Export data in machine-readable format (JSON)
            let export = serde_json::json!({
                "subject_id": subject.id,
                "name": subject.name,
                "email": subject.email,
                "data_categories": subject.data_categories,
                "processing_purposes": subject.processing_purposes,
                "export_date": Utc::now().to_rfc3339(),
            });
            
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Info,
                category: "gdpr_portability".to_string(),
                message: format!("Data portability request fulfilled for subject: {}", subject_id),
                user_id: None,
                resource_id: Some(subject_id.to_string()),
            });
            
            Ok(serde_json::to_vec(&export).unwrap())
        } else {
            Err(format!("Data subject {} not found", subject_id))
        }
    }
}

impl Default for GDPRCompliance {
    fn default() -> Self {
        Self::new()
    }
}

