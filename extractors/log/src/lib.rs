use error::RuntimeError;
use shared::async_nats::{self};
use shared::clap;
use shared::clap::Parser;
use shared::log;
use shared::log_matchers::parse_log_event;
use shared::nats_subjects::Subject;
use shared::nats_util;
use shared::prost::Message;
use shared::protobuf::event::Event;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::tokio::{
    self,
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, BufReader},
    sync::watch,
    time,
};

mod error;

// from libc crate
const O_NONBLOCK: i32 = 2048;

/// The peer-observer log-extractor reads lines from a pipe to a Bitcoin node
/// debug.log pipe (named pipe / FIFO) and publishes parsed lines as events
/// into a NATS pub-sub queue.
#[derive(Parser, Debug)]
#[clap(group(
    clap::ArgGroup::new("pipe")
        .required(true)
        .multiple(false)
        .args(&["bitcoind_pipe"]),
))]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// Path to the bitcoind log pipe (named pipe / FIFO).
    #[arg(short, long)]
    pub bitcoind_pipe: String,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html.
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,
}

pub struct LogExtractor {
    args: Args,
    shutdown_rx: watch::Receiver<bool>,
    nats_client: async_nats::Client,
}

impl LogExtractor {
    pub async fn new(
        args: Args,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<LogExtractor, RuntimeError> {
        let nats_client = nats_util::prepare_connection(&args.nats)?
            .connect(&args.nats.address)
            .await?;
        log::info!("Connected to NATS server at {}", &args.nats.address);

        Ok(LogExtractor {
            args,
            shutdown_rx,
            nats_client,
        })
    }

    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        log::info!(
            "Opening bitcoind log pipe at {}...",
            &self.args.bitcoind_pipe
        );
        let file = self.open_pipe().await?;
        log::info!("Opened bitcoind log pipe at {}", &self.args.bitcoind_pipe);
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        log::info!(
            "Started reading lines from bitcoind log pipe at {}",
            &self.args.bitcoind_pipe
        );
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => self.process_log(&line).await,
                        Ok(None) => {
                            // Since we use O_NONBLOCK, we need to wait here for a
                            // bit to avoid spinning here if we don't have anything
                            // to read.
                            time::sleep(time::Duration::from_millis(25)).await;
                        },
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                // Non-blocking read with no data available: briefly
                                // sleep to avoid spinning here and then continue.
                                time::sleep(time::Duration::from_millis(25)).await;
                                continue;
                            }
                            return Err(e.into());
                        }
                    }
                },
                res = self.shutdown_rx.changed() => {
                    match res {
                        Ok(_) => {
                            if *self.shutdown_rx.borrow() {
                                log::info!("log-extractor received shutdown signal.");
                                break;
                            }
                        }
                        Err(_) => {
                            // all senders dropped -> treat as shutdown
                            log::warn!("The shutdown notification sender was dropped. Shutting down.");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_log(&self, line: &str) {
        log::trace!("Read log line: {}", line);
        match Event::new(PeerObserverEvent::LogExtractor(parse_log_event(line))) {
            Ok(proto) => {
                if let Err(e) = self
                    .nats_client
                    .publish(
                        Subject::LogExtractor.to_string(),
                        proto.encode_to_vec().into(),
                    )
                    .await
                {
                    log::error!("could not publish log into NATS: {}", e);
                } else {
                    log::trace!("published log into NATS: {:?}", proto);
                }
            }
            Err(e) => {
                log::error!("Could not create new Event due to SystemTimeError: {}", e);
            }
        };
    }

    async fn open_pipe(&self) -> Result<File, std::io::Error> {
        let path = &self.args.bitcoind_pipe;

        // Fail after MAX_RETRIES if the pipe doesn't exist yet.
        const MAX_RETRIES: i32 = 30;
        for retries in 0..=MAX_RETRIES {
            if *self.shutdown_rx.borrow() {
                log::info!("open_pipe received shutdown signal.");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "shutdown signal received",
                ));
            }

            if !std::path::Path::new(path).exists() {
                log::warn!(
                    "Pipe {} does not exist yet, retrying in 1s (retry: {}/{})",
                    path,
                    retries,
                    MAX_RETRIES
                );
                time::sleep(time::Duration::from_secs(1)).await;
            } else {
                break;
            }
        }

        OpenOptions::new()
            .read(true)
            .write(false)
            // We need to use O_NONBLOCK here, otherwise a pipe without a writer
            // will block the tokio async routine on next_line() and we can't
            // e.g. CTRL+C anymore.
            .custom_flags(O_NONBLOCK)
            .open(path)
            .await
    }
}
