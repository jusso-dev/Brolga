//! A TAXII server small enough to be a test fixture.
//!
//! Hand-rolled over [`TcpListener`] rather than pulled in as a dependency. A mock HTTP server is
//! about a hundred lines, and the alternative is adding a crate to the supply chain of a project
//! whose whole point is being careful about that — for a fixture, in a security-sensitive crate.
//!
//! It binds port 0 on loopback, so tests never fight for a port and never reach outside the
//! machine. That the connector's own policy would *refuse* loopback is the point of
//! [`crate::support::permissive_policy`]: the tests exercise the protocol against a policy that
//! permits the fixture, and the policy itself is tested separately over addresses rather than over
//! sockets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // A fixture's builders are used by the sibling test file rather than by this one, and
    // `#[must_use]` on a test helper documents nothing a reader of a fixture needs.
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    missing_docs,
    unreachable_pub,
    dead_code
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// The placeholder a reply body may carry for the server's own base URL.
///
/// Discovery has to name the API roots of the server serving it, and the address is not known until
/// the listener binds. Substituting at response time is the only way to write that fixture without
/// starting a throwaway server first to learn a port — which was the earlier shape here, and which
/// pointed every test's API root at a server that had already stopped.
pub const BASE_PLACEHOLDER: &str = "{{BASE}}";

/// One canned answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    /// A `200` carrying a JSON body under a TAXII media type.
    pub fn json(content_type: &str, body: impl Into<String>) -> Self {
        Self {
            status: 200,
            content_type: content_type.to_owned(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// A bare status with no body.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            content_type: String::new(),
            body: String::new(),
            headers: Vec::new(),
        }
    }

    /// A redirect to `location`.
    pub fn redirect(status: u16, location: &str) -> Self {
        Self {
            status,
            content_type: String::new(),
            body: String::new(),
            headers: vec![("Location".to_owned(), location.to_owned())],
        }
    }

    /// The same reply, carrying an extra header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// What a client asked for, so a test can assert on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The request target, including its query string.
    pub target: String,
    /// Request headers, lower-cased.
    pub headers: BTreeMap<String, String>,
}

impl Recorded {
    /// Whether the target carries a query parameter.
    pub fn has_query(&self, needle: &str) -> bool {
        self.target.contains(needle)
    }
}

/// A running mock server.
pub struct MockServer {
    address: SocketAddr,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    served: Arc<AtomicUsize>,
}

impl MockServer {
    /// Start a server answering `routes`, matched by path prefix in order.
    ///
    /// A route may be given several replies; the *n*th request matching it takes the *n*th, and the
    /// last repeats. That is what lets a test drive pagination and conditional requests without any
    /// state machine of its own.
    pub fn start(routes: Vec<(&'static str, Vec<Reply>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
        let address = listener.local_addr().expect("the bound address");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let served = Arc::new(AtomicUsize::new(0));

        let routes: Vec<(String, Vec<Reply>)> = routes
            .into_iter()
            .map(|(path, replies)| (path.to_owned(), replies))
            .collect();

        let thread_recorded = Arc::clone(&recorded);
        let thread_served = Arc::clone(&served);
        let base = format!("http://{address}");

        thread::spawn(move || {
            let mut hits: BTreeMap<String, usize> = BTreeMap::new();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                if handle(
                    stream,
                    &routes,
                    &mut hits,
                    &thread_recorded,
                    &thread_served,
                    &base,
                )
                .is_err()
                {
                    break;
                }
            }
        });

        Self {
            address,
            recorded,
            served,
        }
    }

    /// The base URL to point a client at.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Every request the server received, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.recorded.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// How many requests have been answered.
    pub fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

/// Answer one connection.
fn handle(
    mut stream: TcpStream,
    routes: &[(String, Vec<Reply>)],
    hits: &mut BTreeMap<String, usize>,
    recorded: &Arc<Mutex<Vec<Recorded>>>,
    served: &Arc<AtomicUsize>,
    base: &str,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();

    let mut headers = BTreeMap::new();
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }
    if content_length > 0 {
        let mut body = vec![0_u8; content_length];
        let _ = reader.read_exact(&mut body);
    }

    if let Ok(mut log) = recorded.lock() {
        log.push(Recorded {
            target: target.clone(),
            headers,
        });
    }

    // Longest matching prefix wins, so `/api/collections/x/objects/` is not caught by `/api/`.
    let path = target.split('?').next().unwrap_or(&target).to_owned();
    let matched = routes
        .iter()
        .filter(|(prefix, _)| path.starts_with(prefix.as_str()))
        .max_by_key(|(prefix, _)| prefix.len());

    let mut reply = match matched {
        Some((prefix, replies)) => {
            let index = hits.entry(prefix.clone()).or_insert(0);
            let reply = replies
                .get(*index)
                .or_else(|| replies.last())
                .cloned()
                .unwrap_or_else(|| Reply::status(500));
            *index = index.saturating_add(1);
            reply
        }
        None => Reply::status(404),
    };

    reply.body = reply.body.replace(BASE_PLACEHOLDER, base);
    served.fetch_add(1, Ordering::SeqCst);

    let reason = match reply.status {
        200 => "OK",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };

    let mut response = format!("HTTP/1.1 {} {reason}\r\n", reply.status);
    if !reply.content_type.is_empty() {
        response.push_str(&format!("Content-Type: {}\r\n", reply.content_type));
    }
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    // A 304 must carry no body, and a client that read one anyway would be reading the previous
    // response's bytes.
    if reply.status == 304 {
        response.push_str("Connection: close\r\n\r\n");
    } else {
        response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        response.push_str("Connection: close\r\n\r\n");
        response.push_str(&reply.body);
    }

    stream.write_all(response.as_bytes())?;
    stream.flush()
}
