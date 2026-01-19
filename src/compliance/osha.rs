//! OSHA (Occupational Safety and Health Administration) Compliance
//! 
//! Workplace safety and health compliance for software development environments.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct OSHACompliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    safety_programs: Arc<Mutex<HashMap<String, SafetyProgram>>>,
    training_records: Arc<Mutex<Vec<TrainingRecord>>>,
    incident_reports: Arc<Mutex<Vec<IncidentReport>>>,
    ergonomic_assessments: Arc<Mutex<Vec<ErgonomicAssessment>>>,
    hazard_communications: Arc<Mutex<Vec<HazardCommunication>>>,
}

#[derive(Clone, Debug)]
pub struct SafetyProgram {
    pub id: String,
    pub name: String,
    pub description: String,
    pub requirements: Vec<String>,
    pub implemented: bool,
    pub last_review: DateTime<Utc>,
    pub next_review: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct TrainingRecord {
    pub id: String,
    pub employee_id: String,
    pub training_type: TrainingType,
    pub completed: bool,
    pub completion_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub instructor: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrainingType {
    GeneralSafety,
    ErgonomicSafety,
    FireSafety,
    ElectricalSafety,
    ChemicalSafety,
    EmergencyResponse,
    FirstAid,
}

#[derive(Clone, Debug)]
pub struct IncidentReport {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub employee_id: String,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub description: String,
    pub action_taken: String,
    pub reported_to_osha: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IncidentType {
    Injury,
    Illness,
    NearMiss,
    PropertyDamage,
    Environmental,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IncidentSeverity {
    Minor,
    Moderate,
    Serious,
    Severe,
    Fatal,
}

#[derive(Clone, Debug)]
pub struct ErgonomicAssessment {
    pub id: String,
    pub workstation_id: String,
    pub employee_id: String,
    pub assessment_date: DateTime<Utc>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub implemented: bool,
}

#[derive(Clone, Debug)]
pub struct HazardCommunication {
    pub id: String,
    pub hazard_type: HazardType,
    pub location: String,
    pub description: String,
    pub control_measures: Vec<String>,
    pub communicated_date: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HazardType {
    Physical,
    Chemical,
    Biological,
    Ergonomic,
    Psychosocial,
}

impl OSHACompliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            safety_programs: Arc::new(Mutex::new(Self::initialize_safety_programs())),
            training_records: Arc::new(Mutex::new(Vec::new())),
            incident_reports: Arc::new(Mutex::new(Vec::new())),
            ergonomic_assessments: Arc::new(Mutex::new(Vec::new())),
            hazard_communications: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn initialize_safety_programs() -> HashMap<String, SafetyProgram> {
        let mut programs = HashMap::new();

        programs.insert("ERG-001".to_string(), SafetyProgram {
            id: "ERG-001".to_string(),
            name: "Ergonomic Safety Program".to_string(),
            description: "Program to prevent musculoskeletal disorders in office environments".to_string(),
            requirements: vec![
                "Workstation assessments".to_string(),
                "Adjustable furniture".to_string(),
                "Regular breaks".to_string(),
            ],
            implemented: true,
            last_review: Utc::now(),
            next_review: Utc::now() + chrono::Duration::days(365),
        });

        programs.insert("EYE-001".to_string(), SafetyProgram {
            id: "EYE-001".to_string(),
            name: "Eye Safety Program".to_string(),
            description: "Program to prevent eye strain from computer use".to_string(),
            requirements: vec![
                "Proper lighting".to_string(),
                "Screen filters".to_string(),
                "Regular eye exams".to_string(),
            ],
            implemented: true,
            last_review: Utc::now(),
            next_review: Utc::now() + chrono::Duration::days(365),
        });

        programs.insert("FIRE-001".to_string(), SafetyProgram {
            id: "FIRE-001".to_string(),
            name: "Fire Safety Program".to_string(),
            description: "Program to prevent and respond to fire emergencies".to_string(),
            requirements: vec![
                "Fire extinguishers".to_string(),
                "Evacuation plans".to_string(),
                "Fire drills".to_string(),
            ],
            implemented: true,
            last_review: Utc::now(),
            next_review: Utc::now() + chrono::Duration::days(365),
        });

        programs
    }

    pub fn validate(&self) -> Result<bool, String> {
        let programs = self.safety_programs.lock().unwrap();
        let mut failures = Vec::new();

        // Check all safety programs are implemented
        for (id, program) in programs.iter() {
            if !program.implemented {
                failures.push(format!("Safety program {} not implemented", id));
            }

            // Check programs are reviewed annually
            if program.next_review < Utc::now() {
                failures.push(format!("Safety program {} review overdue", id));
            }
        }

        // Check training records
        let trainings = self.training_records.lock().unwrap();
        let expired_trainings = trainings.iter()
            .filter(|t| {
                if let Some(exp) = t.expiration_date {
                    exp < Utc::now()
                } else {
                    false
                }
            })
            .count();

        if expired_trainings > 0 {
            return Err(format!("OSHA validation failed: {} expired training records found", expired_trainings));
        }

        // Check incident reporting
        let incidents = self.incident_reports.lock().unwrap();
        let serious_incidents = incidents.iter()
            .filter(|i| matches!(i.severity, IncidentSeverity::Serious | IncidentSeverity::Severe | IncidentSeverity::Fatal))
            .filter(|i| !i.reported_to_osha)
            .count();

        if serious_incidents > 0 {
            return Err(format!("OSHA validation failed: {} serious incidents not reported to OSHA", serious_incidents));
        }

        if !failures.is_empty() {
            return Err(format!("OSHA validation failed: {:?}", failures));
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "osha".to_string(),
            message: "OSHA validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn record_training(&self, record: TrainingRecord) -> Result<(), String> {
        let mut trainings = self.training_records.lock().unwrap();
        trainings.push(record.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "osha_training".to_string(),
            message: format!("Training record created: {} for employee {}", record.training_type, record.employee_id),
            user_id: None,
            resource_id: Some(record.id.clone()),
        });

        Ok(())
    }

    pub fn report_incident(&self, incident: IncidentReport) -> Result<(), String> {
        let mut incidents = self.incident_reports.lock().unwrap();
        incidents.push(incident.clone());

        let level = match incident.severity {
            IncidentSeverity::Fatal | IncidentSeverity::Severe => AuditLevel::Error,
            IncidentSeverity::Serious => AuditLevel::Warning,
            _ => AuditLevel::Info,
        };

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level,
            category: "osha_incident".to_string(),
            message: format!("Incident reported: {} - {}", incident.incident_type, incident.description),
            user_id: Some(incident.employee_id.clone()),
            resource_id: Some(incident.id.clone()),
        });

        Ok(())
    }

    pub fn conduct_ergonomic_assessment(&self, assessment: ErgonomicAssessment) -> Result<(), String> {
        let mut assessments = self.ergonomic_assessments.lock().unwrap();
        assessments.push(assessment.clone());

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "osha_ergonomic".to_string(),
            message: format!("Ergonomic assessment conducted for workstation {}", assessment.workstation_id),
            user_id: Some(assessment.employee_id.clone()),
            resource_id: Some(assessment.id.clone()),
        });

        Ok(())
    }
}

impl Default for OSHACompliance {
    fn default() -> Self {
        Self::new()
    }
}

