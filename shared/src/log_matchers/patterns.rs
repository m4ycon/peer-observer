use lazy_static::lazy_static;
use regex::Regex;

/// Regular expression for matching RFC3339-compliant timestamps.
///
/// Matches a timestamp string with the following components:
/// - `\d{4}-\d{2}-\d{2}`: Matches a date in `YYYY-MM-DD` format (four digits for year, two for month, two for day).
/// - `T`: Matches the literal `T` separator between date and time.
/// - `\d{2}:\d{2}:\d{2}`: Matches a time in `HH:MM:SS` format (two digits each for hours, minutes, seconds).
/// - `(?:\.\d{1,6})?`: Optionally matches a fractional second part:
///   - `(?:...)`: Non-capturing group for the decimal part.
///   - `\.\d{1,6}`: Matches a decimal point followed by 1 to 6 digits.
/// - `Z`: Matches the literal `Z` indicating UTC timezone.
pub(crate) static RFC3339_DATE_PATTERN: &str =
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z";

/// Regular expression to capture metadata inside square brackets `[...]`
/// (e.g., log category, thread name, function, etc.).
///
/// Captures: the content between `[` and `]`.
///
/// Breakdown:
/// - `\[`          literal `[`.
/// - `([^\]]+)`    capturing group: one or more characters except `]`.
/// - `\]`          literal `]`.
pub(crate) static METADATA_PATTERN: &str = r"\[([^\]]+)\]";

/// Regular expression for matching a 64-character hexadecimal block hash.
/// Matches strings consisting of exactly 64 characters in the range `0-9` or `a-f`.
pub(crate) static BLOCK_HASH_PATTERN: &str = r"[0-9a-f]{64}";

/// Regular expression for matching the output of `ValidationState::ToString()`.
///
/// Matches strings produced by the `ToString()` method of a validation state object:
/// - `(.*?)`: Captures the **primary reject reason**, non-greedily matching everything up to the first comma and space `", "` or the end of the string.
/// - `(?:,\s|$)`: Non-capturing group that matches either the separator `", "` or the end of the string.
/// - `(.+)?`: Optionally captures the **debug message** that follows the separator, if present.
pub(crate) static VALIDATION_STATE_PATTERN: &str = r"(.*?)(?:,\s|$)(.+)?";

lazy_static! {
    /// Regular expression for parsing default infos from log lines.
    ///
    /// Breakdown:
    /// - `^`                          : Start of line.
    /// - `(?P<timestamp>{})`          : Named capture for the timestamp (uses RFC3339_DATE_PATTERN).
    /// - `\s+`                        : One or more whitespace after timestamp.
    /// - `(?P<metadata>(?:{}\s+)*)`   : Named capture for metadata:
    ///   - `(?:{}\s+)*`               : Zero or more occurrences of METADATA_PATTERN followed by whitespace.
    /// - `(?P<message>.+)$`           : Named capture for the remaining message until end of line.
    pub(crate) static ref LOG_LINE_REGEX: Regex = {
        let pattern = format!(
            r"^(?P<timestamp>{})\s+(?P<metadata>(?:{}\s+)*)(?P<message>.+)$",
            RFC3339_DATE_PATTERN,
            METADATA_PATTERN
        );

        Regex::new(&pattern).unwrap()
    };

    pub(crate) static ref METADATA_REGEX: Regex = Regex::new(METADATA_PATTERN).unwrap();
}
