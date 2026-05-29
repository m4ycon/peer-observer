use crate::{
    log_matchers::{matchers::MATCHERS, parser::{is_standalone_log_level, is_trace, parse_category, parse_log_event}},
    protobuf::log_extractor::{LogDebugCategory, LogLevel, log::LogEvent},
};

#[test]
fn test_log_matcher_unknown_log_message() {
    let log = "2025-10-02T02:31:14Z Verification progress: 50%";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 1759372274000000);
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);
    assert_eq!(log_event.threadname, "");

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "Verification progress: 50%");
        return;
    }

    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_unknown_log_message_with_category() {
    // debug (flags)
    let log = "2025-10-02T02:31:21Z [net] Flushed 0 addresses to peers.dat  2ms";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 1759372281000000);
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(
            unknown_log.raw_message,
            "Flushed 0 addresses to peers.dat  2ms"
        );
        return;
    }

    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_unknown_with_threadname() {
    // logthreadnames (flags)
    let log = "2025-12-23T22:38:01.977182Z [msghand] received: pong (8 bytes) peer=0";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.threadname, "msghand".to_string());
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
        return;
    }

    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_unknown_with_threadname_and_category() {
    // logthreadnames + debug (flags)
    let log = "2025-12-23T22:38:01.977182Z [msghand] [net] received: pong (8 bytes) peer=0";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.threadname, "msghand".to_string());
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
        return;
    }

    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_unknown_with_all_metadata() {
    // logthreadnames + logsourcelocations + debug (flags)
    let log = "2025-12-23T22:38:01.977182Z [msghand] [net_processing.cpp:3452] [ProcessMessage] [net] received: pong (8 bytes) peer=0";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.threadname, "msghand".to_string());
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
        return;
    }

    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_block_connected_with_enqueuing() {
    let log = "2025-09-27T01:52:01Z [validation] Enqueuing BlockConnected: block hash=41109f31c8ca4d8683ab5571ba462292ddb8486dee6ecd2e62901accc7952f0b block height=437";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::BlockConnectedLog(event)) = log_event.log_event {
        assert_eq!(
            event.block_hash,
            "41109f31c8ca4d8683ab5571ba462292ddb8486dee6ecd2e62901accc7952f0b"
        );
        assert_eq!(event.block_height, 437);
        return;
    }

    panic!("Expected BlockConnectedLog event");
}

#[test]
fn test_log_matcher_block_connected() {
    let log = "2025-09-27T01:52:01Z [validation] BlockConnected: block hash=6022a9138d879a9d525dba16a0e7d85eda9874736c1aed5c8da0c23ee878db4f block height=5";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::BlockConnectedLog(event)) = log_event.log_event {
        assert_eq!(
            event.block_hash,
            "6022a9138d879a9d525dba16a0e7d85eda9874736c1aed5c8da0c23ee878db4f"
        );
        assert_eq!(event.block_height, 5);
        return;
    }

    panic!("Expected BlockConnectedLog event");
}

#[test]
fn test_log_matcher_with_logtimemicros_option() {
    let log = "2025-10-17T23:52:01.358911Z [validation] Random message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 1760745121358911);
    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "Random message");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_with_broken_timestamp() {
    let log = "2025--17T23:52:01.358911Z [validation] Random message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 0);
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_with_broken_timestamp2() {
    let log = "2025-99-99T99:99:99.358911Z [validation] Random message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 0);
    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "Random message");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_with_unknown_category() {
    let log = "2025-22-17T23:52:01.358911Z [This-Is-N0t-a-valid-category] Random message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 0);
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "Random message");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_block_checked() {
    let log = "2025-10-28T02:18:37Z [validation] BlockChecked: block hash=3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156 state=Valid";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 1761617917000000);
    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::BlockCheckedLog(event)) = log_event.log_event {
        assert_eq!(
            event.block_hash,
            "3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156"
        );
        assert_eq!(event.state, "Valid");
        assert_eq!(event.debug_message, "");
        return;
    }
    panic!("Expected BlockCheckedLog event");
}

#[test]
fn test_log_matcher_block_checked_with_debug_message() {
    let log = "2025-10-28T02:18:37Z [validation] BlockChecked: block hash=3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156 state=bad-txnmrklroot, hashMerkleRoot mismatch";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.log_timestamp, 1761617917000000);
    assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

    if let Some(LogEvent::BlockCheckedLog(event)) = log_event.log_event {
        assert_eq!(
            event.block_hash,
            "3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156"
        );
        assert_eq!(event.state, "bad-txnmrklroot");
        assert_eq!(event.debug_message, "hashMerkleRoot mismatch");
        return;
    }
    panic!("Expected BlockCheckedLog event");
}

#[test]
fn test_log_matcher_error_level_not_treated_as_threadname() {
    // Bitcoin Core LogError() emits [error] as a log level, not a threadname
    let log = "2025-10-02T02:31:14Z [error] AcceptBlock: bad-witness-nonce-size, CheckWitnessMalleation : invalid witness reserved value size";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);
    assert_eq!(log_event.threadname, "");

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(
                unknown_log.raw_message,
                "AcceptBlock: bad-witness-nonce-size, CheckWitnessMalleation : invalid witness reserved value size"
            );
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_error_level_with_threadname() {
    // [threadname] [error] message - error should be filtered, threadname preserved
    let log = "2025-10-02T02:31:14Z [msghand] [error] some error message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.threadname, "msghand");
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "some error message");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_log_matcher_warning_level_filtered() {
    let log = "2025-10-02T02:31:14Z [warning] some warning message";
    let log_event = parse_log_event(log);

    assert_eq!(log_event.threadname, "");
    assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

    if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
        assert_eq!(unknown_log.raw_message, "some warning message");
        return;
    }
    panic!("Expected UnknownLogMessage event");
}

#[test]
fn test_is_standalone_log_level() {
    assert!(is_standalone_log_level("error"));
    assert!(is_standalone_log_level("Error"));
    assert!(is_standalone_log_level("ERROR"));
    assert!(is_standalone_log_level("warning"));
    assert!(is_standalone_log_level("Warning"));
    // info/debug/trace are NOT standalone bracket tokens in Bitcoin Core
    assert!(!is_standalone_log_level("info"));
    assert!(!is_standalone_log_level("debug"));
    assert!(!is_standalone_log_level("trace"));
    assert!(!is_standalone_log_level("net"));
    assert!(!is_standalone_log_level("validation"));
    assert!(!is_standalone_log_level("msghand"));
    assert!(!is_standalone_log_level("dnsseed"));
}

#[test]
fn test_parse_category() {
    assert_eq!(parse_category("net"), Some(LogDebugCategory::Net));
    assert_eq!(parse_category("net:trace"), Some(LogDebugCategory::Net));
    assert_eq!(
        parse_category("validation"),
        Some(LogDebugCategory::Validation)
    );
    assert_eq!(
        parse_category("validation:trace"),
        Some(LogDebugCategory::Validation)
    );
    assert_eq!(parse_category("This-Is-N0t-a-valid-category"), None);
}

#[test]
fn test_is_trace() {
    assert!(is_trace("net:trace"));
    assert!(is_trace("validation:trace"));
    assert!(!is_trace("net"));
    assert!(!is_trace("validation"));
    assert!(!is_trace("error"));
}

#[test]
fn test_log_level_info_no_category() {
    // LogInfo() emits no bracket and no category — should be INFO
    let log = "2025-10-02T02:31:14Z Verification progress: 50%";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Info as i32);
}

#[test]
fn test_log_level_debug_with_category() {
    // LogDebug(BCLog::NET, ..) emits [net] — should be DEBUG
    let log = "2025-10-02T02:31:21Z [net] Flushed 0 addresses to peers.dat  2ms";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Debug as i32);
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);
}

#[test]
fn test_log_level_debug_with_threadname_and_category() {
    // [threadname] [category] — category implies DEBUG
    let log = "2026-03-08T00:00:21.563170Z [msghand] [net] sending inv (289 bytes) peer=26148";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Debug as i32);
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);
    assert_eq!(log_event.threadname, "msghand");
}

#[test]
fn test_log_level_trace_with_category() {
    // LogTrace(BCLog::NET, ..) emits [net:trace] — should be TRACE
    let log = "2026-03-08T00:00:21.563170Z [net:trace] sending inv (289 bytes) peer=26148";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Trace as i32);
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);
}

#[test]
fn test_log_level_trace_with_threadname_and_category() {
    // [threadname] [category:trace] — should be TRACE
    let log =
        "2026-03-08T00:00:21.563170Z [msghand] [net:trace] sending inv (289 bytes) peer=26148";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Trace as i32);
    assert_eq!(log_event.category, LogDebugCategory::Net as i32);
    assert_eq!(log_event.threadname, "msghand");
}

#[test]
fn test_log_level_error() {
    let log = "2025-10-02T02:31:14Z [error] some error";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Error as i32);
}

#[test]
fn test_log_level_warning() {
    let log = "2025-10-02T02:31:14Z [warning] some warning";
    let log_event = parse_log_event(log);
    assert_eq!(log_event.log_level, LogLevel::Warning as i32);
}

#[test]
fn test_matchers_last_entry_is_catch_all() {
    let last = MATCHERS.last().expect("MATCHERS is empty");
    assert!(
        last("any input xyz").is_some(),
        "last matcher must be catch-all"
    );
}
