use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use super::{respond, serve};

#[test]
fn health_answers_200() {
    let response = respond("GET /health HTTP/1.1");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(r#"{"status":"ok"}"#));
}

#[test]
fn other_paths_methods_and_garbage_are_refused() {
    assert!(respond("GET /v1/node HTTP/1.1").starts_with("HTTP/1.1 404 "));
    assert!(respond("POST /health HTTP/1.1").starts_with("HTTP/1.1 405 "));
    assert!(respond("").starts_with("HTTP/1.1 400 "));
    assert!(respond("GET").starts_with("HTTP/1.1 400 "));
}

#[test]
fn the_server_answers_over_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener));
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nhost: x\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
}
