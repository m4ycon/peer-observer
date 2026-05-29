use crate::log_matchers::matchers::MATCHERS;
use crate::log_matchers::patterns::{LOG_LINE_REGEX, METADATA_REGEX};
use crate::protobuf::log_extractor::{Log, LogDebugCategory, LogLevel};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const NANOS_PER_MICRO: i128 = 1_000;

pub fn parse_log_event(line: &str) -> Log {
    let CommonLogData {
        timestamp_micro,
        category,
        threadname,
        level,
        message,
    } = parse_common_log_data(line);

    for matcher in MATCHERS {
        if let Some(event) = matcher(&message) {
            return Log {
                log_timestamp: timestamp_micro,
                category: category.into(),
                threadname,
                log_level: level.into(),
                log_line_bytes: line.len() as u64,
                log_event: Some(event),
            };
        }
    }

    unreachable!("UnknownLogMessage::parse_event should be the last matcher and always return Some(UnknownLogMessage)");
}

struct CommonLogData {
    pub timestamp_micro: u64,
    pub category: LogDebugCategory,
    pub threadname: String,
    pub level: LogLevel,
    pub message: String,
}

/// Returns `true` if `s` is a standalone Bitcoin Core log level bracket token.
///
/// Only `LogError()` and `LogWarning()` produce standalone bracket tokens
/// (`[error]` and `[warning]`). Other Bitcoin Core log levels never appear as
/// standalone brackets: `LogInfo()` emits no bracket at all, and
/// `LogDebug()`/`LogTrace()` require a category argument so they produce
/// `[category]` or `[category:trace]`, never standalone `[debug]` or `[trace]`.
pub(crate) fn is_standalone_log_level(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "error" | "warning")
}

pub(crate) fn parse_category(item: &str) -> Option<LogDebugCategory> {
    let base = item.strip_suffix(":trace").unwrap_or(item);
    LogDebugCategory::from_str_name(&base.to_uppercase())
}

pub(crate) fn is_trace(item: &str) -> bool {
    item.ends_with(":trace")
}

fn parse_common_log_data(line: &str) -> CommonLogData {
    let caps = LOG_LINE_REGEX.captures(line);
    if caps.is_none() {
        return CommonLogData {
            timestamp_micro: 0,
            level: LogLevel::Info,
            category: LogDebugCategory::Unknown,
            threadname: String::new(),
            message: String::new(),
        };
    }

    let caps = caps.unwrap();

    let timestamp_str = &caps["timestamp"];
    let timestamp_nano = match OffsetDateTime::parse(timestamp_str, &Rfc3339) {
        Ok(dt) => dt.unix_timestamp_nanos(),
        Err(_) => 0,
    };
    let timestamp_micro = (timestamp_nano / NANOS_PER_MICRO) as u64;

    let metadata = caps
        .name("metadata")
        .map(|m| m.as_str())
        .unwrap_or_else(|| "");
    let mut metadata_items: Vec<String> = METADATA_REGEX
        .captures_iter(metadata)
        .map(|cap| cap[1].to_string())
        .collect();

    let mut level = metadata_items
        .iter()
        .find_map(|item| match item.to_lowercase().as_str() {
            "error" => Some(LogLevel::Error),
            "warning" => Some(LogLevel::Warning),
            _ => None,
        })
        .unwrap_or(LogLevel::Info);

    // Filter out log level markers. Bitcoin Core uses LogError(), LogWarning(),
    // etc. which emit [error], [warning], etc. These are log LEVELS, not
    // threadnames or debug categories.
    metadata_items.retain(|item| !is_standalone_log_level(item));

    let mut category = LogDebugCategory::Unknown;
    let mut is_trace_log = false;

    // If exists, category is usually the last metadata item.
    // LogDebug(cat, ..) emits [category], LogTrace(cat, ..) emits [category:trace].
    if let Some(last_item) = metadata_items.last() {
        if let Some(parsed_category) = parse_category(last_item) {
            category = parsed_category;
            is_trace_log = is_trace(last_item);
            metadata_items.pop();
        }
    }

    // LogInfo() emits no category bracket, so a category bracket implies
    // LogDebug or LogTrace. Don't override error/warning.
    if level == LogLevel::Info {
        level = match (category, is_trace_log) {
            (_, true) => LogLevel::Trace,
            (LogDebugCategory::Unknown, _) => LogLevel::Info,
            _ => LogLevel::Debug,
        };
    }

    // if exists, threadname is usually the first metadata item
    let threadname = metadata_items.first().cloned().unwrap_or_default();

    CommonLogData {
        timestamp_micro,
        category,
        threadname,
        level,
        message: caps["message"].to_string(),
    }
}
