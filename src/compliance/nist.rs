//! NIST Cybersecurity Framework Compliance
//! 
//! National Institute of Standards and Technology Cybersecurity Framework
//! implementation for critical infrastructure protection.

use crate::compliance::audit::{AuditTrail, AuditEvent, AuditLevel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

pub struct NISTCompliance {
    audit_trail: Arc<Mutex<AuditTrail>>,
    functions: Arc<Mutex<HashMap<String, FrameworkFunction>>>,
    implementation_tier: Arc<Mutex<ImplementationTier>>,
    profiles: Arc<Mutex<Vec<SecurityProfile>>>,
}

#[derive(Clone, Debug)]
pub struct FrameworkFunction {
    pub id: String,
    pub name: String,
    pub category: FunctionCategory,
    pub outcomes: Vec<Outcome>,
    pub current_state: ImplementationState,
    pub target_state: ImplementationState,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FunctionCategory {
    Identify,
    Protect,
    Detect,
    Respond,
    Recover,
}

#[derive(Clone, Debug)]
pub struct Outcome {
    pub id: String,
    pub description: String,
    pub achieved: bool,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImplementationState {
    NotImplemented,
    PartiallyImplemented,
    LargelyImplemented,
    FullyImplemented,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImplementationTier {
    Tier1, // Partial
    Tier2, // Risk Informed
    Tier3, // Repeatable
    Tier4, // Adaptive
}

#[derive(Clone, Debug)]
pub struct SecurityProfile {
    pub id: String,
    pub name: String,
    pub functions: Vec<String>,
    pub created: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

impl NISTCompliance {
    pub fn new() -> Self {
        Self {
            audit_trail: Arc::new(Mutex::new(AuditTrail::new())),
            functions: Arc::new(Mutex::new(Self::initialize_functions())),
            implementation_tier: Arc::new(Mutex::new(ImplementationTier::Tier3)),
            profiles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn initialize_functions() -> HashMap<String, FrameworkFunction> {
        let mut functions = HashMap::new();

        // ID.AM - Asset Management
        functions.insert("ID.AM-1".to_string(), FrameworkFunction {
            id: "ID.AM-1".to_string(),
            name: "Physical devices and systems within the organization are inventoried".to_string(),
            category: FunctionCategory::Identify,
            outcomes: vec![
                Outcome {
                    id: "ID.AM-1.1".to_string(),
                    description: "Device inventory maintained".to_string(),
                    achieved: true,
                    evidence: vec!["CMDB integration".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // ID.AM-2 - Software platforms and applications
        functions.insert("ID.AM-2".to_string(), FrameworkFunction {
            id: "ID.AM-2".to_string(),
            name: "Software platforms and applications within the organization are inventoried".to_string(),
            category: FunctionCategory::Identify,
            outcomes: vec![
                Outcome {
                    id: "ID.AM-2.1".to_string(),
                    description: "Application inventory maintained".to_string(),
                    achieved: true,
                    evidence: vec!["Software asset management system".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // PR.AC - Identity Management and Access Control
        functions.insert("PR.AC-1".to_string(), FrameworkFunction {
            id: "PR.AC-1".to_string(),
            name: "Identities and credentials are issued, managed, verified, revoked, and audited".to_string(),
            category: FunctionCategory::Protect,
            outcomes: vec![
                Outcome {
                    id: "PR.AC-1.1".to_string(),
                    description: "Identity management system operational".to_string(),
                    achieved: true,
                    evidence: vec!["IAM system deployed".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // PR.DS - Data Security
        functions.insert("PR.DS-1".to_string(), FrameworkFunction {
            id: "PR.DS-1".to_string(),
            name: "Data-at-rest is protected".to_string(),
            category: FunctionCategory::Protect,
            outcomes: vec![
                Outcome {
                    id: "PR.DS-1.1".to_string(),
                    description: "Encryption at rest enabled".to_string(),
                    achieved: true,
                    evidence: vec!["AES-256 encryption".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        functions.insert("PR.DS-2".to_string(), FrameworkFunction {
            id: "PR.DS-2".to_string(),
            name: "Data-in-transit is protected".to_string(),
            category: FunctionCategory::Protect,
            outcomes: vec![
                Outcome {
                    id: "PR.DS-2.1".to_string(),
                    description: "TLS encryption enabled".to_string(),
                    achieved: true,
                    evidence: vec!["TLS 1.3 enforced".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // DE.AE - Anomalies and Events
        functions.insert("DE.AE-1".to_string(), FrameworkFunction {
            id: "DE.AE-1".to_string(),
            name: "A baseline of network operations and expected data flows is established".to_string(),
            category: FunctionCategory::Detect,
            outcomes: vec![
                Outcome {
                    id: "DE.AE-1.1".to_string(),
                    description: "Network baseline established".to_string(),
                    achieved: true,
                    evidence: vec!["Network monitoring system".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // RS.RP - Response Planning
        functions.insert("RS.RP-1".to_string(), FrameworkFunction {
            id: "RS.RP-1".to_string(),
            name: "Response plan is executed during or after a cybersecurity incident".to_string(),
            category: FunctionCategory::Respond,
            outcomes: vec![
                Outcome {
                    id: "RS.RP-1.1".to_string(),
                    description: "Incident response plan documented".to_string(),
                    achieved: true,
                    evidence: vec!["IR playbook available".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        // RC.RP - Recovery Planning
        functions.insert("RC.RP-1".to_string(), FrameworkFunction {
            id: "RC.RP-1".to_string(),
            name: "Recovery plan is executed during or after a cybersecurity incident".to_string(),
            category: FunctionCategory::Recover,
            outcomes: vec![
                Outcome {
                    id: "RC.RP-1.1".to_string(),
                    description: "Disaster recovery plan documented".to_string(),
                    achieved: true,
                    evidence: vec!["DR plan available".to_string()],
                },
            ],
            current_state: ImplementationState::FullyImplemented,
            target_state: ImplementationState::FullyImplemented,
        });

        functions
    }

    pub fn validate(&self) -> Result<bool, String> {
        let functions = self.functions.lock().unwrap();
        let mut failures = Vec::new();

        for (id, function) in functions.iter() {
            // Check if all outcomes are achieved
            let all_achieved = function.outcomes.iter().all(|o| o.achieved);
            if !all_achieved {
                failures.push(format!("{}: Not all outcomes achieved", id));
            }

            // Check if current state meets target state
            if function.current_state < function.target_state {
                failures.push(format!("{}: Current state ({:?}) does not meet target ({:?})", 
                                    id, function.current_state, function.target_state));
            }
        }

        if !failures.is_empty() {
            return Err(format!("NIST Framework validation failed: {:?}", failures));
        }

        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "nist".to_string(),
            message: "NIST Cybersecurity Framework validation passed".to_string(),
            user_id: None,
            resource_id: None,
        });

        Ok(true)
    }

    pub fn update_function_state(&self, id: &str, state: ImplementationState) -> Result<(), String> {
        let mut functions = self.functions.lock().unwrap();
        if let Some(function) = functions.get_mut(id) {
            function.current_state = state.clone();
            
            self.audit_trail.lock().unwrap().log(AuditEvent {
                timestamp: Utc::now(),
                level: AuditLevel::Info,
                category: "nist_function".to_string(),
                message: format!("Function {} state updated to {:?}", id, state),
                user_id: None,
                resource_id: Some(id.to_string()),
            });
            
            Ok(())
        } else {
            Err(format!("Function {} not found", id))
        }
    }

    pub fn set_implementation_tier(&self, tier: ImplementationTier) -> Result<(), String> {
        let mut current_tier = self.implementation_tier.lock().unwrap();
        *current_tier = tier.clone();
        
        self.audit_trail.lock().unwrap().log(AuditEvent {
            timestamp: Utc::now(),
            level: AuditLevel::Info,
            category: "nist_tier".to_string(),
            message: format!("Implementation tier set to {:?}", tier),
            user_id: None,
            resource_id: None,
        });
        
        Ok(())
    }
}

impl PartialOrd for ImplementationState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use std::cmp::Ordering;
        let self_val = match self {
            ImplementationState::NotImplemented => 0,
            ImplementationState::PartiallyImplemented => 1,
            ImplementationState::LargelyImplemented => 2,
            ImplementationState::FullyImplemented => 3,
        };
        let other_val = match other {
            ImplementationState::NotImplemented => 0,
            ImplementationState::PartiallyImplemented => 1,
            ImplementationState::LargelyImplemented => 2,
            ImplementationState::FullyImplemented => 3,
        };
        Some(self_val.cmp(&other_val))
    }
}

impl Default for NISTCompliance {
    fn default() -> Self {
        Self::new()
    }
}

