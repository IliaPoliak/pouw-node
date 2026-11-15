use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
};

use super::{Upstream, UpstreamError};

/// An HTTP answer.
pub(crate) fn http(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.0 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A full node on a free port that gives `answers` to its next connections, one each.
/// Joining the thread gives the requests it received.
pub(crate) fn fake_node(answers: Vec<Vec<u8>>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for answer in answers {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            requests.push(String::from_utf8(request).unwrap());
            stream.write_all(&answer).unwrap();
        }
        requests
    });
    (url, handle)
}

/// A URL where nothing listens.
pub(crate) fn dead_node() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

#[test]
fn the_answer_is_read_with_its_status_type_and_body() {
    let (url, node) = fake_node(vec![http("200 OK", "application/json", br#"{"a":1}"#)]);
    let answer = Upstream::new(&[url]).get("/v1/x", true).unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.content_type, "application/json");
    assert_eq!(answer.body, br#"{"a":1}"#);
    let requests = node.join().unwrap();
    assert!(
        requests[0].starts_with("GET /v1/x HTTP/1.0\r\n"),
        "{requests:?}"
    );
    assert!(
        requests[0].contains("accept: application/json"),
        "{requests:?}"
    );
}

#[test]
fn borsh_is_asked_for_when_json_is_not() {
    let (url, node) = fake_node(vec![http("200 OK", "application/octet-stream", &[1, 2])]);
    let answer = Upstream::new(&[url]).get("/v1/x", false).unwrap();
    assert_eq!(answer.body, [1, 2]);
    let requests = node.join().unwrap();
    assert!(
        requests[0].contains("accept: application/octet-stream"),
        "{requests:?}"
    );
}

#[test]
fn a_404_is_an_answer_and_a_5xx_or_a_dead_node_moves_on_to_the_next() {
    let (broken, broken_node) =
        fake_node(vec![http("500 Internal Server Error", "text/plain", b"x")]);
    let (live, live_node) = fake_node(vec![http("404 Not Found", "application/json", b"{}")]);
    let upstream = Upstream::new(&[dead_node(), broken, live]);
    let answer = upstream.get("/v1/x", true).unwrap();
    assert_eq!(answer.status, 404);
    assert_eq!(broken_node.join().unwrap().len(), 1);
    assert_eq!(live_node.join().unwrap().len(), 1);
}

#[test]
fn without_a_reachable_full_node_there_is_an_error() {
    let none = Upstream::new(&[]);
    assert!(none.is_empty());
    assert!(matches!(
        none.get("/v1/x", true),
        Err(UpstreamError::NoNodes)
    ));
    let dead = Upstream::new(&[dead_node()]);
    assert!(matches!(
        dead.get("/v1/x", true),
        Err(UpstreamError::Unreachable(_))
    ));
    let (garbage, node) = fake_node(vec![b"nonsense".to_vec()]);
    assert!(matches!(
        Upstream::new(&[garbage]).get("/v1/x", true),
        Err(UpstreamError::Unreachable(_))
    ));
    node.join().unwrap();
}

#[test]
fn only_http_nodes_are_used_and_the_port_defaults_to_80() {
    let upstream = Upstream::new(&[
        "https://secure.example".to_owned(),
        "http://plain.example".to_owned(),
        "http://127.0.0.1:8000".to_owned(),
    ]);
    assert_eq!(upstream.len(), 2);
}
