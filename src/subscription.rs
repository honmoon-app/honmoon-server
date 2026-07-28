use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    PastDue,
    GracePeriod,
    Canceled,
    Expired,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionInfo {
    pub status: SubscriptionStatus,
    pub trial_days_remaining: Option<i64>,
    pub grace_days_remaining: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialResult {
    Started { trial_end: i64 },
    AlreadyActive,
    AlreadyUsedByDevice,
    AlreadyUsedByEmail,
}

/// Returns true if the subscription status allows access to premium features
pub fn is_allowed(status: &SubscriptionStatus) -> bool {
    matches!(
        status,
        SubscriptionStatus::Trialing
            | SubscriptionStatus::Active
            | SubscriptionStatus::PastDue
            | SubscriptionStatus::GracePeriod
    )
}
