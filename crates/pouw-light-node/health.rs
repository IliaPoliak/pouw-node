//! A tiny HTTP server for `/health`. It answers one request per connection and closes
//! it, which is all a Docker healthcheck or `curl` needs. The light API of
//! pouw-node#102 replaces it with a router.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use pouw_api::path::HEALTH;
use tracing::{debug, warn};

/// Most bytes of a request head the server reads.
const MAX_HEAD_BYTES: u64 = 8192;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Accepts connections until the process ends, one thread per connection.
pub fn serve(listener: &TcpListener) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle(stream) {
                        debug!(%error, "health connection failed");
                    }
                });
            }
            Err(error) => warn!(%error, "cannot accept a connection"),
        }
    }
}

fn handle(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let head = read_head(&stream)?;
    let response = respond(&head);
    stream.write_all(response.as_bytes())
}

/// The request line and the headers, which are read so that closing the connection does
/// not reset it before the client reads the answer.
fn read_head(stream: &TcpStream) -> io::Result<String> {
    let mut reader = BufReader::new(stream.take(MAX_HEAD_BYTES));
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line.trim_end().is_empty() {
            break;
        }
    }
    Ok(first)
}

/// The full HTTP response for a request line such as `GET /health HTTP/1.1`.
pub fn respond(request_line: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let (status, body) = match (parts.next(), parts.next()) {
        (Some("GET"), Some(HEALTH)) => ("200 OK", r#"{"status":"ok"}"#),
        (Some("GET"), Some(_)) => ("404 Not Found", r#"{"code":"not_found"}"#),
        (Some(_), Some(_)) => ("405 Method Not Allowed", r#"{"code":"method_not_allowed"}"#),
        _ => ("400 Bad Request", r#"{"code":"bad_request"}"#),
    };
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests;
