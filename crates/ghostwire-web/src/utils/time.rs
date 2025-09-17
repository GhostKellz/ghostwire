/// Time formatting utilities
///
/// Functions for formatting timestamps and durations in a user-friendly way.

use chrono::{DateTime, Utc, Duration};

/// Format a timestamp relative to now (e.g., "5 minutes ago", "2 hours ago")
pub fn format_relative_time(timestamp: DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now.signed_duration_since(timestamp);

    if diff < Duration::zero() {
        return "in the future".to_string();
    }

    if diff.num_seconds() < 60 {
        "just now".to_string()
    } else if diff.num_minutes() < 60 {
        let minutes = diff.num_minutes();
        if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        }
    } else if diff.num_hours() < 24 {
        let hours = diff.num_hours();
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if diff.num_days() < 7 {
        let days = diff.num_days();
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if diff.num_weeks() < 4 {
        let weeks = diff.num_weeks();
        if weeks == 1 {
            "1 week ago".to_string()
        } else {
            format!("{} weeks ago", weeks)
        }
    } else {
        // For older dates, show the actual date
        timestamp.format("%Y-%m-%d").to_string()
    }
}

/// Format a duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    let seconds = duration.num_seconds();

    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        let remaining_seconds = seconds % 60;
        if remaining_seconds == 0 {
            format!("{}m", minutes)
        } else {
            format!("{}m {}s", minutes, remaining_seconds)
        }
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let remaining_minutes = (seconds % 3600) / 60;
        if remaining_minutes == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, remaining_minutes)
        }
    } else {
        let days = seconds / 86400;
        let remaining_hours = (seconds % 86400) / 3600;
        if remaining_hours == 0 {
            format!("{}d", days)
        } else {
            format!("{}d {}h", days, remaining_hours)
        }
    }
}

/// Format an absolute timestamp for display
pub fn format_absolute_time(timestamp: DateTime<Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Format a timestamp with timezone for display
pub fn format_local_time(timestamp: DateTime<Utc>) -> String {
    // In a real app, you'd use the user's timezone
    // For now, we'll just show UTC
    timestamp.format("%Y-%m-%d %H:%M").to_string()
}