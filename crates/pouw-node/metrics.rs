//! The Prometheus metrics. node-api.md requires the four in [`REQUIRED`]; the full
//! list belongs to the metrics contract. The node loop owns one [`Metrics`], its
//! handlers update it and [`render`] writes it in the text exposition format.
//! [`DROPPED_REPLIES`], [`DROPPED_COMMANDS`] and [`DROPPED_BLOCKS`] are the metrics beyond
//! the contract, as are the network metrics [`MESSAGES_RECEIVED`], [`MESSAGES_SENT`] and
//! [`BLOCK_RECEIVE_DELAY_SECONDS`] (next to [`PEERS`]).

use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc;

use crate::{api::ApiRequest, node::ComponentFault, p2p::Topic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// A value that goes up and down.
    Gauge,
    /// A count that only goes up.
    Counter,
    /// A distribution of observations.
    Histogram,
}

/// One metric as it appears on `/metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metric {
    /// Name, with the `pouw_node_` prefix.
    pub name: &'static str,
    /// The `# HELP` text.
    pub help: &'static str,
    /// The `# TYPE`.
    pub kind: MetricKind,
}

/// Height of the canonical tip.
pub const HEIGHT: Metric = Metric {
    name: "pouw_node_height",
    help: "Height of the canonical tip.",
    kind: MetricKind::Gauge,
};

/// Pending transactions.
pub const MEMPOOL_SIZE: Metric = Metric {
    name: "pouw_node_mempool_size",
    help: "Transactions in the mempool.",
    kind: MetricKind::Gauge,
};

pub const PEERS: Metric = Metric {
    name: "pouw_node_peers",
    help: "Connected peers.",
    kind: MetricKind::Gauge,
};

/// Wall time of one block verification.
pub const VERIFICATION_DURATION_SECONDS: Metric = Metric {
    name: "pouw_node_verification_duration_seconds",
    help: "Wall time of verifying one block.",
    kind: MetricKind::Histogram,
};

/// Replies the loop could not deliver because the caller stopped waiting.
pub const DROPPED_REPLIES: Metric = Metric {
    name: "pouw_node_dropped_replies_total",
    help: "Replies dropped because the caller was gone.",
    kind: MetricKind::Counter,
};

/// Received blocks the loop dropped because the verify queue was full.
pub const DROPPED_BLOCKS: Metric = Metric {
    name: "pouw_node_dropped_blocks_total",
    help: "Received blocks dropped because the verify queue was full.",
    kind: MetricKind::Counter,
};

/// Commands to the transport the loop dropped because the command channel was full.
pub const DROPPED_COMMANDS: Metric = Metric {
    name: "pouw_node_dropped_commands_total",
    help: "Commands to the transport dropped because its channel was full.",
    kind: MetricKind::Counter,
};

/// Connected blocks, counted when a block extends the tip.
pub const BLOCKS_CONNECTED: Metric = Metric {
    name: "pouw_node_blocks_connected_total",
    help: "Blocks connected on top of the tip.",
    kind: MetricKind::Counter,
};

/// Proof txs in the connected blocks, so proofs per block is the rate of this over the
/// rate of [`BLOCKS_CONNECTED`].
pub const BLOCK_PROOFS: Metric = Metric {
    name: "pouw_node_block_proofs_total",
    help: "Proof transactions in connected blocks.",
    kind: MetricKind::Counter,
};

/// Header timestamp of a connected block minus the one of its parent.
pub const BLOCK_TIME_SECONDS: Metric = Metric {
    name: "pouw_node_block_time_seconds",
    help: "Seconds between a connected block and its parent, by header timestamps.",
    kind: MetricKind::Histogram,
};

/// Nonces this node tried while mining, the attempts of the lottery.
pub const LOTTERY_ATTEMPTS: Metric = Metric {
    name: "pouw_node_lottery_attempts_total",
    help: "Nonces tried by the miner of this node.",
    kind: MetricKind::Counter,
};

/// What a message between two nodes is, the label `kind` of [`MESSAGES_RECEIVED`] and
/// [`MESSAGES_SENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A block announcement on the gossip topic of blocks.
    BlockAnnounce,
    /// A transfer or a circuit registration on the gossip topic of coin transactions.
    CoinTx,
    /// A proof request on the gossip topic of proof requests.
    ProofRequest,
    /// The status a peer sends once after it connects.
    Status,
    /// A `GetHeaders` or a `GetBlocks`.
    SyncRequest,
    /// The answer to a [`MessageKind::SyncRequest`].
    SyncResponse,
}

/// How many [`MessageKind`]s there are.
pub const MESSAGE_KINDS: usize = 6;

impl MessageKind {
    pub const ALL: [Self; MESSAGE_KINDS] = [
        Self::BlockAnnounce,
        Self::CoinTx,
        Self::ProofRequest,
        Self::Status,
        Self::SyncRequest,
        Self::SyncResponse,
    ];

    /// The value of the label `kind`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::BlockAnnounce => "block_announce",
            Self::CoinTx => "coin_tx",
            Self::ProofRequest => "proof_request",
            Self::Status => "status",
            Self::SyncRequest => "sync_request",
            Self::SyncResponse => "sync_response",
        }
    }

    /// The place of the kind in [`MessageKind::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::BlockAnnounce => 0,
            Self::CoinTx => 1,
            Self::ProofRequest => 2,
            Self::Status => 3,
            Self::SyncRequest => 4,
            Self::SyncResponse => 5,
        }
    }

    /// The kind of a gossip message on `topic`.
    pub const fn of_topic(topic: Topic) -> Self {
        match topic {
            Topic::BlockAnnounce => Self::BlockAnnounce,
            Topic::CoinTxs => Self::CoinTx,
            Topic::ProofRequests => Self::ProofRequest,
        }
    }
}

/// Messages received from peers and handed to the loop, by kind. A sync answer counts
/// when it passed the precheck of the transport; one that failed does not.
pub const MESSAGES_RECEIVED: Metric = Metric {
    name: "pouw_node_messages_received_total",
    help: "Messages received from peers, by kind.",
    kind: MetricKind::Counter,
};

/// Messages the loop handed to the transport to send, by kind. A broadcast counts once,
/// however many peers the transport sends it to.
pub const MESSAGES_SENT: Metric = Metric {
    name: "pouw_node_messages_sent_total",
    help: "Messages handed to the transport to send, by kind.",
    kind: MetricKind::Counter,
};

/// Seconds between the header timestamp of a block a peer announces and the moment the
/// announcement arrives, for the first announcement of a block that passes the header
/// rules. The timestamp is set by the miner before it seals the block, and the clocks of
/// two nodes differ, so this is an upper bound of the delay in the network with the
/// mining time and the clock skew in it; a negative value counts as 0.
pub const BLOCK_RECEIVE_DELAY_SECONDS: Metric = Metric {
    name: "pouw_node_block_receive_delay_seconds",
    help: "Seconds between the header timestamp of an announced block and its arrival.",
    kind: MetricKind::Histogram,
};

/// The metrics every node exports.
pub const REQUIRED: [Metric; 4] = [HEIGHT, MEMPOOL_SIZE, PEERS, VERIFICATION_DURATION_SECONDS];

/// The values behind [`REQUIRED`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metrics {
    /// [`HEIGHT`], refreshed on every tick.
    pub height: u64,
    /// [`MEMPOOL_SIZE`], refreshed on every tick.
    pub mempool_size: u64,
    /// [`PEERS`].
    pub peers: u64,
    /// Count of [`VERIFICATION_DURATION_SECONDS`].
    pub verifications: u64,
    /// Sum of [`VERIFICATION_DURATION_SECONDS`].
    pub verification_time: Duration,
    /// [`DROPPED_REPLIES`].
    pub dropped_replies: u64,
    /// [`DROPPED_COMMANDS`].
    pub dropped_commands: u64,
    /// [`DROPPED_BLOCKS`].
    pub dropped_blocks: u64,
    /// [`BLOCKS_CONNECTED`], also the count of [`BLOCK_TIME_SECONDS`].
    pub blocks_connected: u64,
    /// [`BLOCK_PROOFS`].
    pub block_proofs: u64,
    /// Sum of [`BLOCK_TIME_SECONDS`] in seconds.
    pub block_time_secs: u64,
    /// [`LOTTERY_ATTEMPTS`].
    pub lottery_attempts: u64,
    /// [`MESSAGES_RECEIVED`], by [`MessageKind::index`].
    pub messages_received: [u64; MESSAGE_KINDS],
    /// [`MESSAGES_SENT`], by [`MessageKind::index`].
    pub messages_sent: [u64; MESSAGE_KINDS],
    /// Count of [`BLOCK_RECEIVE_DELAY_SECONDS`].
    pub block_delays: u64,
    /// Sum of [`BLOCK_RECEIVE_DELAY_SECONDS`] in seconds.
    pub block_delay_secs: u64,
}

impl Metrics {
    /// Counts a message of `kind` received.
    pub fn received(&mut self, kind: MessageKind) {
        if let Some(count) = self.messages_received.get_mut(kind.index()) {
            *count = count.saturating_add(1);
        }
    }

    /// Counts a message of `kind` handed to the transport.
    pub fn sent(&mut self, kind: MessageKind) {
        if let Some(count) = self.messages_sent.get_mut(kind.index()) {
            *count = count.saturating_add(1);
        }
    }

    /// How many messages of `kind` were received.
    pub fn received_of(&self, kind: MessageKind) -> u64 {
        self.messages_received
            .get(kind.index())
            .copied()
            .unwrap_or(0)
    }

    /// How many messages of `kind` were handed to the transport.
    pub fn sent_of(&self, kind: MessageKind) -> u64 {
        self.messages_sent.get(kind.index()).copied().unwrap_or(0)
    }
}

/// The text exposition of every metric of [`REQUIRED`], [`DROPPED_REPLIES`],
/// [`DROPPED_COMMANDS`] and [`DROPPED_BLOCKS`].
pub fn render(metrics: &Metrics) -> String {
    let mut sections: Vec<String> = [
        (HEIGHT, metrics.height),
        (MEMPOOL_SIZE, metrics.mempool_size),
        (PEERS, metrics.peers),
        (DROPPED_REPLIES, metrics.dropped_replies),
        (DROPPED_COMMANDS, metrics.dropped_commands),
        (DROPPED_BLOCKS, metrics.dropped_blocks),
        (BLOCKS_CONNECTED, metrics.blocks_connected),
        (BLOCK_PROOFS, metrics.block_proofs),
        (LOTTERY_ATTEMPTS, metrics.lottery_attempts),
    ]
    .into_iter()
    .map(|(metric, value)| format!("{}{} {value}\n", header(metric), metric.name))
    .collect();
    let metric = VERIFICATION_DURATION_SECONDS;
    sections.push(format!(
        "{header}{name}_bucket{{le=\"+Inf\"}} {count}\n{name}_sum {sum}\n{name}_count {count}\n",
        header = header(metric),
        name = metric.name,
        count = metrics.verifications,
        sum = metrics.verification_time.as_secs_f64(),
    ));
    let metric = BLOCK_TIME_SECONDS;
    sections.push(format!(
        "{header}{name}_bucket{{le=\"+Inf\"}} {count}\n{name}_sum {sum}\n{name}_count {count}\n",
        header = header(metric),
        name = metric.name,
        count = metrics.blocks_connected,
        sum = metrics.block_time_secs,
    ));
    for (metric, counts) in [
        (MESSAGES_RECEIVED, &metrics.messages_received),
        (MESSAGES_SENT, &metrics.messages_sent),
    ] {
        let lines: String = MessageKind::ALL
            .into_iter()
            .zip(counts)
            .map(|(kind, count)| {
                [
                    metric.name,
                    "{kind=\"",
                    kind.label(),
                    "\"} ",
                    &count.to_string(),
                    "\n",
                ]
                .concat()
            })
            .collect();
        sections.push(format!("{}{lines}", header(metric)));
    }
    let metric = BLOCK_RECEIVE_DELAY_SECONDS;
    sections.push(format!(
        "{header}{name}_bucket{{le=\"+Inf\"}} {count}\n{name}_sum {sum}\n{name}_count {count}\n",
        header = header(metric),
        name = metric.name,
        count = metrics.block_delays,
        sum = metrics.block_delay_secs,
    ));
    sections.concat()
}

/// The `/metrics` thread: answers scrapes on `addr` with the text of
/// [`crate::api::ApiRequest::Metrics`], see [`crate::http`].
pub fn serve(addr: SocketAddr, api: &mpsc::Sender<ApiRequest>) -> Result<(), ComponentFault> {
    crate::http::serve_metrics(addr, api)
}

fn header(metric: Metric) -> String {
    let kind = match metric.kind {
        MetricKind::Gauge => "gauge",
        MetricKind::Counter => "counter",
        MetricKind::Histogram => "histogram",
    };
    format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n",
        name = metric.name,
        help = metric.help
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_required_metric_is_rendered() {
        let metrics = Metrics {
            height: 7,
            verifications: 2,
            verification_time: Duration::from_millis(1500),
            ..Metrics::default()
        };
        let text = render(&metrics);
        for metric in REQUIRED {
            assert!(text.contains(&format!("# TYPE {} ", metric.name)));
        }
        assert!(text.contains("pouw_node_height 7\n"));
        assert!(text.contains("# TYPE pouw_node_dropped_replies_total counter\n"));
        assert!(text.contains("pouw_node_dropped_replies_total 0\n"));
        assert!(text.contains("pouw_node_dropped_commands_total 0\n"));
        assert!(text.contains("pouw_node_dropped_blocks_total 0\n"));
        assert!(text.contains("pouw_node_verification_duration_seconds_sum 1.5\n"));
        assert!(text.contains("pouw_node_verification_duration_seconds_count 2\n"));
    }

    #[test]
    fn the_block_production_metrics_are_rendered() {
        let metrics = Metrics {
            blocks_connected: 4,
            block_proofs: 3,
            block_time_secs: 40,
            lottery_attempts: 9000,
            ..Metrics::default()
        };
        let text = render(&metrics);
        assert!(text.contains("# TYPE pouw_node_blocks_connected_total counter\n"));
        assert!(text.contains("pouw_node_blocks_connected_total 4\n"));
        assert!(text.contains("pouw_node_block_proofs_total 3\n"));
        assert!(text.contains("pouw_node_lottery_attempts_total 9000\n"));
        assert!(text.contains("# TYPE pouw_node_block_time_seconds histogram\n"));
        assert!(text.contains("pouw_node_block_time_seconds_sum 40\n"));
        assert!(text.contains("pouw_node_block_time_seconds_count 4\n"));
    }

    #[test]
    fn the_network_metrics_are_rendered_by_kind() {
        let mut metrics = Metrics {
            block_delays: 2,
            block_delay_secs: 9,
            ..Metrics::default()
        };
        metrics.received(MessageKind::CoinTx);
        metrics.received(MessageKind::CoinTx);
        metrics.sent(MessageKind::SyncResponse);
        assert_eq!(metrics.received_of(MessageKind::CoinTx), 2);
        assert_eq!(metrics.received_of(MessageKind::Status), 0);
        assert_eq!(metrics.sent_of(MessageKind::SyncResponse), 1);
        let text = render(&metrics);
        assert!(text.contains("# TYPE pouw_node_messages_received_total counter\n"));
        assert!(text.contains("pouw_node_messages_received_total{kind=\"coin_tx\"} 2\n"));
        assert!(text.contains("pouw_node_messages_received_total{kind=\"status\"} 0\n"));
        assert!(text.contains("pouw_node_messages_sent_total{kind=\"sync_response\"} 1\n"));
        assert!(text.contains("# TYPE pouw_node_block_receive_delay_seconds histogram\n"));
        assert!(text.contains("pouw_node_block_receive_delay_seconds_sum 9\n"));
        assert!(text.contains("pouw_node_block_receive_delay_seconds_count 2\n"));
        // every kind has a line of its own, in the order of ALL
        for (place, kind) in MessageKind::ALL.into_iter().enumerate() {
            assert_eq!(kind.index(), place);
            let line = format!("pouw_node_messages_sent_total{{kind=\"{}\"}}", kind.label());
            assert_eq!(text.matches(&line).count(), 1);
        }
    }

    #[test]
    fn names_are_those_of_the_contract() {
        let names: Vec<&str> = REQUIRED.iter().map(|m| m.name).collect();
        assert_eq!(
            names,
            [
                "pouw_node_height",
                "pouw_node_mempool_size",
                "pouw_node_peers",
                "pouw_node_verification_duration_seconds"
            ]
        );
    }
}
