/// Alerting system for GhostWire observability
///
/// Provides configurable alerting based on metrics thresholds and health check failures.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::{AlertConfig, AlertRule, AlertSeverity, EmailConfig, GhostWireMetrics};

#[derive(Debug, Clone)]
pub struct AlertManager {
    config: AlertConfig,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    metrics: Arc<GhostWireMetrics>,
    notification_sender: Option<NotificationSender>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub triggered_at: SystemTime,
    pub resolved_at: Option<SystemTime>,
    pub status: AlertStatus,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Firing,
    Resolved,
    Silenced,
}

#[derive(Debug, Clone)]
enum NotificationSender {
    Webhook { url: String, client: reqwest::Client },
    Email { config: EmailConfig },
}

impl AlertManager {
    /// Create a new alert manager
    pub async fn new(config: AlertConfig, metrics: Arc<GhostWireMetrics>) -> Result<Self> {
        let notification_sender = if config.enabled {
            if let Some(ref webhook_url) = config.webhook_url {
                Some(NotificationSender::Webhook {
                    url: webhook_url.clone(),
                    client: reqwest::Client::new(),
                })
            } else if let Some(ref email_config) = config.email_config {
                Some(NotificationSender::Email {
                    config: email_config.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            notification_sender,
        })
    }

    /// Evaluate all alert rules
    pub async fn evaluate_rules(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok();
        }

        for rule in &self.config.rules {
            if let Err(e) = self.evaluate_rule(rule).await {
                error!("Failed to evaluate alert rule '{}': {}", rule.name, e);
            }
        }

        Ok(())
    }

    /// Evaluate a single alert rule
    async fn evaluate_rule(&self, rule: &AlertRule) -> Result<()> {
        let alert_id = format!("{}_{}", rule.name, rule.metric);
        let current_value = self.get_metric_value(&rule.metric).await?;
        let should_fire = self.evaluate_condition(current_value, rule)?;

        let mut alerts = self.active_alerts.write().await;

        match alerts.get(&alert_id) {
            Some(existing_alert) if existing_alert.status == AlertStatus::Firing => {
                if !should_fire {
                    // Resolve the alert
                    let mut resolved_alert = existing_alert.clone();
                    resolved_alert.status = AlertStatus::Resolved;
                    resolved_alert.resolved_at = Some(SystemTime::now());

                    alerts.insert(alert_id.clone(), resolved_alert.clone());

                    info!("Alert resolved: {}", rule.name);
                    self.send_notification(&resolved_alert, NotificationType::Resolved).await?;
                }
            }
            _ => {
                if should_fire {
                    // Fire new alert
                    let alert = Alert {
                        id: alert_id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        message: format!(
                            "Alert '{}': {} {} {} (current value: {:.2})",
                            rule.name,
                            rule.metric,
                            rule.condition,
                            rule.threshold,
                            current_value
                        ),
                        triggered_at: SystemTime::now(),
                        resolved_at: None,
                        status: AlertStatus::Firing,
                        labels: HashMap::new(),
                        annotations: HashMap::new(),
                    };

                    alerts.insert(alert_id, alert.clone());

                    warn!("Alert fired: {}", alert.message);
                    self.send_notification(&alert, NotificationType::Firing).await?;

                    // Record alert metrics
                    self.metrics.record_event("alert_fired", &[
                        ("rule", &rule.name),
                        ("severity", &format!("{:?}", rule.severity)),
                    ]);
                }
            }
        }

        Ok(())
    }

    /// Get current value for a metric
    async fn get_metric_value(&self, metric_name: &str) -> Result<f64> {
        // This is a simplified implementation
        // In a real system, you'd query the actual metric values
        match metric_name {
            "cpu_usage" => Ok(25.0), // Mock CPU usage
            "memory_usage" => Ok(65.0), // Mock memory usage
            "disk_usage" => Ok(45.0), // Mock disk usage
            "connection_errors" => Ok(2.0), // Mock error count
            "response_time" => Ok(150.0), // Mock response time in ms
            _ => Ok(0.0),
        }
    }

    /// Evaluate alert condition
    fn evaluate_condition(&self, current_value: f64, rule: &AlertRule) -> Result<bool> {
        match rule.condition.as_str() {
            ">" | "gt" => Ok(current_value > rule.threshold),
            ">=" | "gte" => Ok(current_value >= rule.threshold),
            "<" | "lt" => Ok(current_value < rule.threshold),
            "<=" | "lte" => Ok(current_value <= rule.threshold),
            "==" | "eq" => Ok((current_value - rule.threshold).abs() < f64::EPSILON),
            "!=" | "ne" => Ok((current_value - rule.threshold).abs() >= f64::EPSILON),
            _ => Err(anyhow::anyhow!("Unknown condition: {}", rule.condition)),
        }
    }

    /// Send notification for an alert
    async fn send_notification(&self, alert: &Alert, notification_type: NotificationType) -> Result<()> {
        if let Some(ref sender) = self.notification_sender {
            match sender {
                NotificationSender::Webhook { url, client } => {
                    self.send_webhook_notification(url, client, alert, notification_type).await
                }
                NotificationSender::Email { config } => {
                    self.send_email_notification(config, alert, notification_type).await
                }
            }
        } else {
            Ok(())
        }
    }

    /// Send webhook notification
    async fn send_webhook_notification(
        &self,
        url: &str,
        client: &reqwest::Client,
        alert: &Alert,
        notification_type: NotificationType,
    ) -> Result<()> {
        let payload = WebhookPayload {
            alert: alert.clone(),
            notification_type,
            timestamp: SystemTime::now(),
        };

        let response = client
            .post(url)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Webhook notification sent successfully");
        } else {
            warn!("Webhook notification failed: {}", response.status());
        }

        Ok(())
    }

    /// Send email notification
    async fn send_email_notification(
        &self,
        _config: &EmailConfig,
        alert: &Alert,
        notification_type: NotificationType,
    ) -> Result<()> {
        // Email sending implementation would go here
        // For now, just log the notification
        info!(
            "Email notification: {:?} for alert '{}'",
            notification_type, alert.rule_name
        );
        Ok(())
    }

    /// Get all active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.active_alerts.read().await;
        alerts
            .values()
            .filter(|alert| alert.status == AlertStatus::Firing)
            .cloned()
            .collect()
    }

    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<Alert> {
        let alerts = self.active_alerts.read().await;
        let mut all_alerts: Vec<Alert> = alerts.values().cloned().collect();

        // Sort by triggered_at in descending order
        all_alerts.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));

        if let Some(limit) = limit {
            all_alerts.truncate(limit);
        }

        all_alerts
    }

    /// Silence an alert
    pub async fn silence_alert(&self, alert_id: &str, duration: Duration) -> Result<()> {
        let mut alerts = self.active_alerts.write().await;

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Silenced;
            info!("Alert '{}' silenced for {:?}", alert_id, duration);

            // Schedule alert to be unsilenced
            let alerts_clone = self.active_alerts.clone();
            let alert_id = alert_id.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                let mut alerts = alerts_clone.write().await;
                if let Some(alert) = alerts.get_mut(&alert_id) {
                    if alert.status == AlertStatus::Silenced {
                        alert.status = AlertStatus::Firing;
                        info!("Alert '{}' unsilenced", alert_id);
                    }
                }
            });

            Ok(())
        } else {
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.active_alerts.write().await;

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.annotations.insert("acknowledged".to_string(), "true".to_string());
            alert.annotations.insert(
                "acknowledged_at".to_string(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
            );

            info!("Alert '{}' acknowledged", alert_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Get alert statistics
    pub async fn get_alert_stats(&self) -> AlertStats {
        let alerts = self.active_alerts.read().await;

        let total_alerts = alerts.len();
        let firing_alerts = alerts.values().filter(|a| a.status == AlertStatus::Firing).count();
        let resolved_alerts = alerts.values().filter(|a| a.status == AlertStatus::Resolved).count();
        let silenced_alerts = alerts.values().filter(|a| a.status == AlertStatus::Silenced).count();

        let critical_alerts = alerts
            .values()
            .filter(|a| {
                a.status == AlertStatus::Firing && matches!(a.severity, AlertSeverity::Critical)
            })
            .count();

        AlertStats {
            total_alerts,
            firing_alerts,
            resolved_alerts,
            silenced_alerts,
            critical_alerts,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum NotificationType {
    Firing,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookPayload {
    alert: Alert,
    notification_type: NotificationType,
    timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: usize,
    pub firing_alerts: usize,
    pub resolved_alerts: usize,
    pub silenced_alerts: usize,
    pub critical_alerts: usize,
}

/// Create default alert rules for GhostWire
pub fn create_default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            name: "high_cpu_usage".to_string(),
            metric: "cpu_usage".to_string(),
            condition: ">".to_string(),
            threshold: 80.0,
            duration: Duration::from_secs(300), // 5 minutes
            severity: AlertSeverity::Warning,
        },
        AlertRule {
            name: "high_memory_usage".to_string(),
            metric: "memory_usage".to_string(),
            condition: ">".to_string(),
            threshold: 85.0,
            duration: Duration::from_secs(300),
            severity: AlertSeverity::Warning,
        },
        AlertRule {
            name: "critical_memory_usage".to_string(),
            metric: "memory_usage".to_string(),
            condition: ">".to_string(),
            threshold: 95.0,
            duration: Duration::from_secs(60),
            severity: AlertSeverity::Critical,
        },
        AlertRule {
            name: "high_disk_usage".to_string(),
            metric: "disk_usage".to_string(),
            condition: ">".to_string(),
            threshold: 90.0,
            duration: Duration::from_secs(600), // 10 minutes
            severity: AlertSeverity::Warning,
        },
        AlertRule {
            name: "connection_errors".to_string(),
            metric: "connection_errors".to_string(),
            condition: ">".to_string(),
            threshold: 10.0,
            duration: Duration::from_secs(60),
            severity: AlertSeverity::Critical,
        },
        AlertRule {
            name: "slow_response_time".to_string(),
            metric: "response_time".to_string(),
            condition: ">".to_string(),
            threshold: 1000.0, // 1 second
            duration: Duration::from_secs(300),
            severity: AlertSeverity::Warning,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetricsConfig;

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let config = AlertConfig {
            enabled: true,
            webhook_url: Some("http://example.com/webhook".to_string()),
            email_config: None,
            rules: create_default_alert_rules(),
        };

        let metrics_config = MetricsConfig::default();
        let metrics = Arc::new(GhostWireMetrics::new(&metrics_config).unwrap());

        let alert_manager = AlertManager::new(config, metrics).await;
        assert!(alert_manager.is_ok());
    }

    #[test]
    fn test_default_alert_rules() {
        let rules = create_default_alert_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.name == "high_cpu_usage"));
        assert!(rules.iter().any(|r| r.name == "high_memory_usage"));
    }

    #[tokio::test]
    async fn test_alert_stats() {
        let config = AlertConfig {
            enabled: false,
            webhook_url: None,
            email_config: None,
            rules: vec![],
        };

        let metrics_config = MetricsConfig::default();
        let metrics = Arc::new(GhostWireMetrics::new(&metrics_config).unwrap());

        let alert_manager = AlertManager::new(config, metrics).await.unwrap();
        let stats = alert_manager.get_alert_stats().await;

        assert_eq!(stats.total_alerts, 0);
        assert_eq!(stats.firing_alerts, 0);
    }
}