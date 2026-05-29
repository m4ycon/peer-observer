use crate::log_matchers::patterns::{BLOCK_HASH_PATTERN, VALIDATION_STATE_PATTERN};
use crate::protobuf::log_extractor::log::LogEvent;
use crate::protobuf::log_extractor::{BlockCheckedLog, BlockConnectedLog, UnknownLogMessage};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref BLOCK_CONNECTED_REGEX: Regex = Regex::new(&format!(
        r"BlockConnected: block hash=({}) block height=(\d+)",
        BLOCK_HASH_PATTERN
    ))
    .unwrap();
    static ref BLOCK_CHECKED_REGEX: Regex = Regex::new(&format!(
        r"BlockChecked: block hash=({}) state={}",
        BLOCK_HASH_PATTERN, VALIDATION_STATE_PATTERN
    ))
    .unwrap();
}

trait LogMatcher {
    fn parse_event(line: &str) -> Option<LogEvent>;
}

impl LogMatcher for UnknownLogMessage {
    fn parse_event(line: &str) -> Option<LogEvent> {
        Some(LogEvent::UnknownLogMessage(UnknownLogMessage {
            raw_message: line.to_string(),
        }))
    }
}

impl LogMatcher for BlockConnectedLog {
    fn parse_event(line: &str) -> Option<LogEvent> {
        let caps = BLOCK_CONNECTED_REGEX.captures(line)?;

        let block_hash = caps.get(1)?.as_str().to_string();
        let block_height = caps.get(2)?.as_str().parse::<u32>().ok()?;
        Some(LogEvent::BlockConnectedLog(BlockConnectedLog {
            block_hash,
            block_height,
        }))
    }
}

impl LogMatcher for BlockCheckedLog {
    fn parse_event(line: &str) -> Option<LogEvent> {
        let caps = BLOCK_CHECKED_REGEX.captures(line)?;

        let block_hash = caps.get(1)?.as_str().to_string();
        let state = caps.get(2)?.as_str().to_string();
        let debug_message = caps
            .get(3)
            .map_or_else(String::new, |m| m.as_str().to_string());
        Some(LogEvent::BlockCheckedLog(BlockCheckedLog {
            block_hash,
            state,
            debug_message,
        }))
    }
}

impl BlockCheckedLog {
    pub fn is_mutated_block(&self) -> bool {
        matches!(
            self.state.as_str(),
            "bad-txnmrklroot"
                | "bad-txns-duplicate"
                | "bad-witness-nonce-size"
                | "bad-witness-merkle-match"
                | "unexpected-witness"
        )
    }
}

pub const MATCHERS: &[fn(&str) -> Option<LogEvent>] = &[
    BlockConnectedLog::parse_event,
    BlockCheckedLog::parse_event,
    UnknownLogMessage::parse_event, // if no matcher succeeds, this MUST be the last entry
];
