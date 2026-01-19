//! Automated Audit Trail and Reporting System
//! 
//! Comprehensive audit logging for compliance and security monitoring.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

pub struct AuditTrail {
    events: Arc<Mutex<VecDeque<AuditEvent>>>,
    max_events: usize,
    retention_days: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub level: AuditLevel,
    pub category: String,
    pub message: String,
    pub user_id: Option<String>,
    pub resource_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AuditLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            max_events: 100000,
            retention_days: 2555, // 7 years for compliance
        }
    }

    pub fn log(&mut self, event: AuditEvent) {
        let mut events = self.events.lock().unwrap();
        
        // Enforce retention policy
        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days);
        while let Some(front) = events.front() {
            if front.timestamp < cutoff {
                events.pop_front();
            } else {
                break;
            }
        }

        // Enforce max events
        while events.len() >= self.max_events {
            events.pop_front();
        }

        events.push_back(event);
    }

    pub fn query(&self, 
                 start_time: Option<DateTime<Utc>>,
                 end_time: Option<DateTime<Utc>>,
                 category: Option<&str>,
                 level: Option<AuditLevel>,
                 user_id: Option<&str>) -> Vec<AuditEvent> {
        let events = self.events.lock().unwrap();
        let start = start_time.unwrap_or(DateTime::from_timestamp(0, 0).unwrap());
        let end = end_time.unwrap_or(Utc::now());

        events.iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .filter(|e| category.map_or(true, |c| e.category == c))
            .filter(|e| level.as_ref().map_or(true, |l| e.level == *l))
            .filter(|e| user_id.map_or(true, |u| e.user_id.as_ref().map_or(false, |uid| uid == u)))
            .cloned()
            .collect()
    }

    pub fn generate_report(&self, 
                          start_time: DateTime<Utc>,
                          end_time: DateTime<Utc>) -> AuditReport {
        let events = self.query(Some(start_time), Some(end_time), None, None, None);
        
        let mut level_counts = std::collections::HashMap::new();
        let mut category_counts = std::collections::HashMap::new();
        
        for event in &events {
            *level_counts.entry(format!("{:?}", event.level)).or_insert(0) += 1;
            *category_counts.entry(event.category.clone()).or_insert(0) += 1;
        }

        AuditReport {
            start_time,
            end_time,
            total_events: events.len(),
            level_counts,
            category_counts,
            events: events.into_iter().take(1000).collect(), // Limit for performance
        }
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let events = self.events.lock().unwrap();
        serde_json::to_string_pretty(&events.iter().collect::<Vec<_>>())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub total_events: usize,
    pub level_counts: std::collections::HashMap<String, usize>,
    pub category_counts: std::collections::HashMap<String, usize>,
    pub events: Vec<AuditEvent>,
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

