#![cfg(feature = "nats_integration_tests")]

use shared::{
    futures::{stream, SinkExt, StreamExt},
    log::{self, warn},
    nats_subjects::Subject,
    nats_util::NatsArgs,
    prost::Message,
    protobuf::{
        ebpf_extractor::{
            connection::{self, Connection},
            ebpf,
            mempool::{self, Added},
            message::{self, message_event::Msg, Metadata, Ping, Pong},
            validation::{self, BlockConnected},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
    },
    rand::{self, Rng},
    simple_logger::SimpleLogger,
    testing::{nats_publisher::NatsPublisherForTesting, nats_server::NatsServerForTesting},
    tokio::{
        self,
        sync::{watch, Mutex},
        time::{sleep, timeout},
    },
};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

use std::{
    io::ErrorKind,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Once, OnceLock,
    },
    time::Duration,
};

use websocket::{error::RuntimeError, Args, ClientSubscriptions, ClientSubscriptionsEbpf};

const SUBSCRIBE_NONE: ClientSubscriptions = ClientSubscriptions {
    ebpf: ClientSubscriptionsEbpf {
        messages: false,
        mempool: false,
        validation: false,
        connections: false,
        addrman: false,
    },
    p2p: false,
    log: false,
    rpc: false,
};

const SUBSCRIBE_ALL: ClientSubscriptions = ClientSubscriptions {
    ebpf: ClientSubscriptionsEbpf {
        messages: true,
        mempool: true,
        validation: true,
        connections: true,
        addrman: true,
    },
    p2p: true,
    log: true,
    rpc: true,
};

#[derive(Debug, Clone)]
struct ClientConfig {
    subscriptions: ClientSubscriptions,
    expected_events: Vec<&'static str>,
    disconnect: bool, // whether to disconnect this client before receiving messages
}

static INIT: Once = Once::new();

static NEXT_WEBSOCKET_PORT: OnceLock<AtomicU16> = OnceLock::new();

fn setup() -> u16 {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();

        let mut rng = rand::rng();

        // choose start ports from the ephemeral port range
        let websocket_start = rng.random_range(49152..65500);
        NEXT_WEBSOCKET_PORT
            .set(AtomicU16::new(websocket_start))
            .unwrap();
    });

    let websocket_port = NEXT_WEBSOCKET_PORT
        .get()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    websocket_port
}

fn make_test_args(nats_port: u16, websocket_port: u16) -> Args {
    Args::new(
        NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        format!("127.0.0.1:{}", websocket_port),
        log::Level::Trace,
    )
}

async fn publish_and_check_simple(
    events: &[(Subject, Event)],
    expected_events: Vec<&'static str>,
    num_clients: Option<u8>,
) {
    let num_clients = num_clients.unwrap_or(1);
    let clients = vec![
        ClientConfig {
            subscriptions: SUBSCRIBE_ALL.clone(),
            expected_events: expected_events.to_vec(),
            disconnect: false,
        };
        num_clients as usize
    ];

    publish_and_check(events, clients.as_slice()).await;
}

async fn publish_and_check(events: &[(Subject, Event)], clients: &[ClientConfig]) {
    let initial_websocket_port = setup();
    let websocket_port: Arc<Mutex<u16>> = Arc::new(Mutex::new(initial_websocket_port));

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let websocket_port_clone = websocket_port.clone();
    let websocket_handle = tokio::spawn(async move {
        loop {
            let port: u16;
            {
                port = *websocket_port_clone.lock().await;
            }

            let args = make_test_args(nats_server.port, port);
            match websocket::run(args, shutdown_rx.clone()).await {
                Ok(_) => break,
                Err(e) => match e {
                    RuntimeError::Io(e) => match e.kind() {
                        ErrorKind::AddrInUse => {
                            let new_port = NEXT_WEBSOCKET_PORT
                                .get()
                                .unwrap()
                                .fetch_add(1, Ordering::SeqCst);
                            warn!(
                                "Port {} seems to be already in use. Trying port {} next..",
                                port, new_port
                            );
                            let mut port = websocket_port_clone.lock().await;
                            *port = new_port;
                        }
                        _ => panic!("Couldn not start websocket tool: {}", e),
                    },
                    _ => panic!("Couldn not start websocket tool: {}", e),
                },
            }
        }
    });
    // allow the websocket tool to start
    sleep(Duration::from_secs(1)).await;

    let port = websocket_port.lock().await;
    let mut clients_stream = vec![];
    for client_config in clients {
        let (ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}", port))
            .await
            .expect("Should be able to connect to websocket");
        let (mut outgoing, incoming) = ws_stream.split();
        outgoing
            .send(TungsteniteMessage::Text(
                serde_json::to_string(&client_config.subscriptions)
                    .unwrap()
                    .into(),
            ))
            .await
            .expect("Should be able to send subscription message");
        clients_stream.push((outgoing, incoming));
    }

    for (subject, event) in events.iter() {
        log::debug!("publishing: {:?}", event);
        nats_publisher
            .publish(subject.to_string(), event.encode_to_vec())
            .await;
    }

    for (i, client_config) in clients.iter().enumerate() {
        if client_config.disconnect {
            let outgoing = &mut clients_stream[i].0;
            outgoing
                .close()
                .await
                .expect("Should be able to close a client");
        }
    }

    stream::iter(clients_stream)
        .enumerate()
        .map(async |(i, (_, mut incoming))| {
            let client_config = &clients[i];
            if client_config.disconnect {
                // if we closed this client, we can skip it here as we don't expect it to have all events
                return;
            }

            let mut messages = vec![];
            timeout(Duration::from_secs(1), async {
                while let Some(msg) = incoming.next().await {
                    messages.push(msg.unwrap());
                }
            })
            .await
            .unwrap_or(());

            assert_eq!(client_config.expected_events.len(), messages.len()); // not less, not more

            for (i, expected) in client_config.expected_events.iter().enumerate() {
                let msg = &messages[i];
                assert_eq!(*expected, msg.to_string());
            }
        })
        .buffer_unordered(clients.len())
        .collect::<Vec<_>>()
        .await;

    shutdown_tx.send(true).unwrap();
    websocket_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_websocket_conn_inbound() {
    println!("test that inbound connections work");

    publish_and_check(
        &[(
            Subject::NetConn,
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                    event: Some(connection::connection_event::Event::Inbound(
                        connection::InboundConnection {
                            conn: Connection {
                                addr: "127.0.0.1:8333".to_string(),
                                conn_type: 1,
                                network: 2,
                                peer_id: 7,
                            },
                            existing_connections: 123,
                        },
                    )),
                })),
            }))
            .unwrap(),
        )],
        &[ClientConfig {
            subscriptions: SUBSCRIBE_ALL.clone(),
            expected_events: vec![
                r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Inbound":{"conn":{"peer_id":7,"addr":"127.0.0.1:8333","conn_type":1,"network":2},"existing_connections":123}}}}}}"#,
            ],
            disconnect: false,
        }],
    ).await;
}

#[tokio::test]
async fn test_integration_websocket_p2p_message_ping() {
    println!("test that the P2P message via websockets work");

    publish_and_check(
        &[
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1 })),
                }))
            }))
            .unwrap()),
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "pong".to_string(),
                        inbound: false,
                        size: 8,
                    },
                    msg: Some(Msg::Pong(Pong { value: 1 })),
                }))
            }))
            .unwrap(),)
        ],
        &[
          ClientConfig {
              subscriptions: SUBSCRIBE_ALL.clone(),
              expected_events: vec![
                  r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
                  r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#],
              disconnect: false,
          },
        ]
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_multi_client() {
    println!("test that multiple clients all receive the messages");

    publish_and_check_simple(
        &[
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1 })),
                }))
            }))
            .unwrap()),
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "pong".to_string(),
                        inbound: false,
                        size: 8,
                    },
                    msg: Some(Msg::Pong(Pong { value: 1 })),
                }))
            }))
            .unwrap()),
        ],
        vec![r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
            r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#],
        Some(12),
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_closed_client() {
    println!(
        "test that we can close a client connection and the others will still receive the messages"
    );

    publish_and_check(
        &[(Subject::NetConn, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                event: Some(connection::connection_event::Event::Outbound(
                    connection::OutboundConnection {
                        conn: Connection {
                            addr: "1.1.1.1:48333".to_string(),
                            conn_type: 2,
                            network: 3,
                            peer_id: 11,
                        },
                        existing_connections: 321,
                    },
                )),
            }))
        }))
        .unwrap())],
        &[
            ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![
                    r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Outbound":{"conn":{"peer_id":11,"addr":"1.1.1.1:48333","conn_type":2,"network":3},"existing_connections":321}}}}}}"#,
                ],
                disconnect: false,
            },
              ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![],
                disconnect: true,
            },
              ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![
                    r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Outbound":{"conn":{"peer_id":11,"addr":"1.1.1.1:48333","conn_type":2,"network":3},"existing_connections":321}}}}}}"#,
                ],
                disconnect: false,
            },
        ],
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_specific_subjects() {
    println!("test that we can subscribe to specific subjects and only receive those events");

    let mut subscriptions = SUBSCRIBE_NONE.clone();
    subscriptions.ebpf.mempool = true;

    publish_and_check(
        &[
            (Subject::Mempool, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
                    event: Some(mempool::mempool_event::Event::Added(Added {
                        txid: vec![76, 70, 231],
                        vsize: 175,
                        fee: 358,
                    })),
                }))
            }))
            .unwrap()),
            (Subject::Validation, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Validation(validation::ValidationEvent {
                    event: Some(validation::validation_event::Event::BlockConnected(BlockConnected {
                        hash: vec![1, 2, 3, 4, 5],
                        height: 800000,
                        transactions: 2500,
                        inputs: 5000,
                        sigops: 20000,
                        connection_time: 1500000000,
                    })),
                }))
            }))
            .unwrap()),
        ],
        &[
              ClientConfig {
                  subscriptions,
                  expected_events: vec![
                      r#"{"EbpfExtractor":{"ebpf_event":{"Mempool":{"event":{"Added":{"txid":[76,70,231],"vsize":175,"fee":358}}}}}}"#,
                  ],
                  disconnect: false,
              },
              ClientConfig {
                  subscriptions: SUBSCRIBE_NONE.clone(),
                  expected_events: vec![],
                  disconnect: false,
              },
        ]
    )
    .await;
}
