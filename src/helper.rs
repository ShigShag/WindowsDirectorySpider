use std::time::{SystemTime, UNIX_EPOCH};

// Helper function to safely convert SystemTime to the desired format
pub fn format_system_time(time: Result<SystemTime, std::io::Error>) -> Option<String> {
    if let Ok(system_time) = time {
        let timestamp = system_time_to_unix_timestamp(system_time);
        Some(format!("/Date({})/", timestamp))
    } else {
        None // Return None if there's an error (e.g., if the file system doesn't support certain metadata)
    }
}

// Convert SystemTime to a Unix timestamp in milliseconds, handling errors safely
fn system_time_to_unix_timestamp(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}