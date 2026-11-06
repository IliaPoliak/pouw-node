//! The Prometheus metrics. node-api.md requires the four in [`REQUIRED`]; the full
//! list belongs to the metrics contract. The node loop owns one [`Metrics`], its
//! handlers update it and [`render`] writes it in the text exposition format.
//! [`DROPPED_REPLIES`], [`DROPPED_COMMANDS`] and [`DROPPED_BLOCKS`] are the metrics beyond
//! the contract.

use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc;

use crate::{api::ApiRequest, node::ComponentFault};

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
