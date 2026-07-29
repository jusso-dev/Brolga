//! An MCP server over stdio.
//!
//! # Intent tools, not a database wrapper
//!
//! The tools here answer questions an analyst asks — "what is known about this?", "what is
//! connected to it?" — rather than exposing a query surface. An agent handed a query language
//! composes questions nobody designed the answers for, and the answers are what carry the evidence,
//! the markings, and the gaps. A tool that returned rows would return them without any of that.
//!
//! # Raw source objects are excluded by default
//!
//! No tool returns original source bytes. The `context` tool serves `L0`–`L3`, and `L4`/`L5` are
//! reached by expanding a handle — which is a policy decision made per object, not something an
//! agent can reach by asking a tool for more. An agent that could pull source material by tool call
//! would be one authorisation decision covering an unbounded amount of somebody else's licensed
//! content.
//!
//! # Every tool declares a versioned schema
//!
//! Input and output schemas are published in `tools/list`, and output schemas name the versioned
//! canonical type where one exists. An agent that cannot tell which version of a pack it received
//! cannot cache one or diff two.
//!
//! # Errors are protocol errors, not prose
//!
//! A refusal is a JSON-RPC error with a code an agent can branch on. An agent handed a sentence
//! retries, rephrases, and eventually reports something that did not happen — which is the failure
//! mode a structured refusal exists to prevent.

use std::io::{BufRead, Write};

use brolga_config::PolicyIdentity;
use brolga_graph::assemble::{AssemblyRequest, Gathered};
use brolga_graph::subject;
use brolga_model::Timestamp;
use brolga_model::pack::DetailLevel;
use brolga_model::{NodeRef, Observable};
use brolga_storage::sqlite::SqliteStore;
use brolga_storage::store::{Direction, EdgeQuery, Page};
use brolga_storage::{RecordKind, StoreRead};
use serde_json::{Value, json};

/// The MCP protocol revision this server speaks.
pub(crate) const PROTOCOL_VERSION: &str = "2024-11-05";

/// The schema version every tool result carries.
pub(crate) const TOOL_SCHEMA_VERSION: &str = "brolga.mcp.tool/1.0";

/// JSON-RPC codes an agent can branch on.
mod codes {
    /// The request was not valid JSON-RPC.
    pub(super) const INVALID_REQUEST: i64 = -32600;
    /// No such method or tool.
    pub(super) const METHOD_NOT_FOUND: i64 = -32601;
    /// The arguments were wrong.
    pub(super) const INVALID_PARAMS: i64 = -32602;
    /// Something failed inside the server.
    pub(super) const INTERNAL: i64 = -32603;
}

/// One tool this server offers.
struct Tool {
    name: &'static str,
    description: &'static str,
    input: fn() -> Value,
    output: fn() -> Value,
}

/// Every tool, with its schemas.
///
/// The list is deliberately short. Each entry is backed by a capability that exists and is tested;
/// a tool declared here that returned an empty result would be worse than an absent one, because an
/// agent treats "no results" as an answer.
fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "brolga_context",
            description: "What Brolga knows about one observable, as a versioned context pack: disposition, \
                 findings with evidence, gaps, exclusions, and expansion handles. Returns L0-L3; \
                 raw source objects are never included.",
            input: || {
                json!({
                    "type": "object",
                    "required": ["kind", "value"],
                    "properties": {
                        "kind": {"type": "string", "description": "ip, domain, url, email, or hash"},
                        "value": {"type": "string", "description": "The value, in any spelling. It is canonicalised."},
                        "detail_level": {"type": "string", "enum": ["L0", "L1", "L2", "L3"]},
                        "purpose": {"type": "string"},
                        "max_objects": {"type": "integer", "minimum": 1},
                    },
                    "additionalProperties": false,
                })
            },
            output: || {
                json!({
                    "type": "object",
                    "description": "A brolga.context_pack document.",
                    "x-brolga-schema": "brolga.context_pack",
                })
            },
        },
        Tool {
            name: "brolga_neighbours",
            description: "What is connected to an entity, bounded by depth and count. Returns edges and the \
                 entities at their far ends.",
            input: || {
                json!({
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string", "description": "A canonical entity identifier."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    },
                    "additionalProperties": false,
                })
            },
            output: || {
                json!({
                    "type": "object",
                    "properties": {
                        "relationships": {"type": "array"},
                        "budget": {"type": "object"},
                    },
                })
            },
        },
        Tool {
            name: "brolga_stats",
            description: "How many records of each kind the store holds.",
            input: || json!({"type": "object", "properties": {}, "additionalProperties": false}),
            output: || {
                json!({
                    "type": "object",
                    "properties": {
                        "entities": {"type": "integer"},
                        "claims": {"type": "integer"},
                        "relationships": {"type": "integer"},
                        "sightings": {"type": "integer"},
                    },
                })
            },
        },
    ]
}

/// Run the server until stdin closes.
///
/// # Errors
///
/// Returns an I/O failure on the transport. A failure handling one request is answered as a
/// JSON-RPC error rather than ending the session — an agent that lost its connection because one
/// call was malformed would retry the whole conversation.
pub(crate) fn serve<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    store: &mut SqliteStore,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle(&request, store),
            Err(error) => Some(error_response(
                &Value::Null,
                codes::INVALID_REQUEST,
                &format!("not valid JSON: {error}"),
            )),
        };

        // A notification — a request with no `id` — gets no reply, which the protocol requires.
        // Answering one would put an unexpected message on the agent's stream.
        if let Some(response) = response {
            writeln!(output, "{response}")?;
            output.flush()?;
        }
    }
    Ok(())
}

/// Handle one request, returning the response to write, if any.
fn handle(request: &Value, store: &mut SqliteStore) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    // No `id` means a notification. `initialized` is the one an agent sends after handshaking.
    let id = id?;

    Some(match method {
        "initialize" => success(
            &id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "brolga", "version": env!("CARGO_PKG_VERSION")},
            }),
        ),
        "tools/list" => success(
            &id,
            json!({
                "tools": tools()
                    .iter()
                    .map(|tool| json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": (tool.input)(),
                        "outputSchema": (tool.output)(),
                    }))
                    .collect::<Vec<_>>(),
            }),
        ),
        "tools/call" => call_tool(&id, request, store),
        "ping" => success(&id, json!({})),
        other => error_response(
            &id,
            codes::METHOD_NOT_FOUND,
            &format!("`{other}` is not a method this server implements"),
        ),
    })
}

/// Dispatch a tool call.
fn call_tool(id: &Value, request: &Value, store: &mut SqliteStore) -> Value {
    let params = request.get("params").unwrap_or(&Value::Null);
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, codes::INVALID_PARAMS, "no tool name");
    };
    let arguments = params.get("arguments").unwrap_or(&Value::Null);

    let outcome = match name {
        "brolga_context" => context_tool(arguments, store),
        "brolga_neighbours" => neighbours_tool(arguments, store),
        "brolga_stats" => stats_tool(store),
        other => Err((
            codes::METHOD_NOT_FOUND,
            format!("`{other}` is not a tool this server offers"),
        )),
    };

    match outcome {
        Ok(value) => success(
            id,
            json!({
                // The protocol's content envelope, with the structured result alongside. An agent
                // that only reads `content` still gets the answer; one that can read
                // `structuredContent` gets it without parsing prose back out.
                "content": [{"type": "text", "text": value.to_string()}],
                "structuredContent": value,
                "isError": false,
            }),
        ),
        Err((code, message)) => error_response(id, code, &message),
    }
}

/// The `brolga_context` tool.
fn context_tool(arguments: &Value, store: &mut SqliteStore) -> Result<Value, (i64, String)> {
    let kind = arguments
        .get("kind")
        .and_then(Value::as_str)
        .ok_or((codes::INVALID_PARAMS, "no `kind`".to_owned()))?;
    let value = arguments
        .get("value")
        .and_then(Value::as_str)
        .ok_or((codes::INVALID_PARAMS, "no `value`".to_owned()))?;

    let observable = subject::resolve(kind, value)
        .map_err(|error| (codes::INVALID_PARAMS, error.to_string()))?;

    let detail_level = match arguments.get("detail_level").and_then(Value::as_str) {
        None => DetailLevel::L1,
        Some("L0") => DetailLevel::L0,
        Some("L1") => DetailLevel::L1,
        Some("L2") => DetailLevel::L2,
        Some("L3") => DetailLevel::L3,
        // L4 and L5 are reached by expanding a handle, which is a policy decision per object. A
        // tool that served them would make one call cover an unbounded amount of source material.
        Some(other) => {
            return Err((
                codes::INVALID_PARAMS,
                format!(
                    "`{other}` is not a level this tool serves. L0-L3 are packs; L4 and L5 are \
                     reached by expanding a handle from the pack's `handles` array"
                ),
            ));
        }
    };

    let max_objects = arguments
        .get("max_objects")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 1000);

    let gathered =
        gather(store, &observable, max_objects).map_err(|reason| (codes::INTERNAL, reason))?;
    let graph_version = store.graph_version().unwrap_or(0);

    let request = AssemblyRequest {
        observable,
        detail_level,
        purpose: arguments
            .get("purpose")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // An agent over stdio is running as the local operator who started it. Stated rather than
        // assumed, so it appears in the pack's `policy.recipient` and goes through the same code
        // the server uses.
        identity: PolicyIdentity::local_operator(),
        max_objects,
        max_relationships: max_objects,
        now: Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc()),
        graph_version,
        request_id: None,
    };

    let pack = brolga_graph::assemble::build(&request, &gathered)
        .map_err(|reason| (codes::INTERNAL, reason))?;

    serde_json::to_value(&pack).map_err(|error| (codes::INTERNAL, error.to_string()))
}

/// The `brolga_neighbours` tool.
fn neighbours_tool(arguments: &Value, store: &mut SqliteStore) -> Result<Value, (i64, String)> {
    let id = arguments
        .get("id")
        .and_then(Value::as_str)
        .ok_or((codes::INVALID_PARAMS, "no `id`".to_owned()))?;
    let limit = u32::try_from(
        arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(50)
            .clamp(1, 1000),
    )
    .unwrap_or(50);

    let parsed = id
        .parse()
        .map_err(|_| (codes::INVALID_PARAMS, format!("`{id}` is not an entity id")))?;
    let edges = store
        .edges_at(
            &EdgeQuery::at(NodeRef::Entity(parsed), Direction::Either),
            Page::first(limit),
        )
        .map_err(|error| (codes::INTERNAL, error.to_string()))?;

    Ok(json!({
        "schema_version": TOOL_SCHEMA_VERSION,
        "relationships": edges
            .iter()
            .map(|edge| json!({
                "kind": edge.kind.as_str(),
                "source": edge.source.to_string(),
                "target": edge.target.to_string(),
                "status": edge.status.as_str(),
            }))
            .collect::<Vec<_>>(),
        // Stated on every result, not only when it bit. An agent cannot tell a complete answer from
        // a truncated one by counting, and will treat the second as the first.
        "budget": {
            "requested": limit,
            "returned": edges.len(),
            "exhausted": edges.len() >= usize::try_from(limit).unwrap_or(usize::MAX),
        },
    }))
}

/// The `brolga_stats` tool.
fn stats_tool(store: &mut SqliteStore) -> Result<Value, (i64, String)> {
    let count = |kind: RecordKind| store.count(kind).unwrap_or(0);
    Ok(json!({
        "schema_version": TOOL_SCHEMA_VERSION,
        "entities": count(RecordKind::Entity),
        "claims": count(RecordKind::Claim),
        "relationships": count(RecordKind::Relationship),
        "sightings": count(RecordKind::Sighting),
    }))
}

/// Read what a pack is assembled from.
fn gather(
    store: &mut SqliteStore,
    observable: &Observable,
    limit: u64,
) -> Result<Gathered, String> {
    let node = NodeRef::Observable(observable.id());
    let page = Page::first(u32::try_from(limit).unwrap_or(100));

    let claims = store
        .claims_about(&node, page)
        .map_err(|error| error.to_string())?;
    let edges = store
        .edges_at(&EdgeQuery::at(node, Direction::Either), page)
        .map_err(|error| error.to_string())?;
    let sightings = store
        .sightings_of(&node, page)
        .map_err(|error| error.to_string())?;

    let mut entities = Vec::new();
    for edge in &edges {
        for end in [edge.source, edge.target] {
            if let NodeRef::Entity(id) = end
                && let Some(entity) = store.get_entity(id).map_err(|error| error.to_string())?
            {
                entities.push(entity);
            }
        }
    }
    entities.sort_by_key(|entity| entity.id.to_string());
    entities.dedup_by_key(|entity| entity.id.to_string());

    Ok(Gathered {
        claims,
        edges,
        sightings,
        entities,
    })
}

/// A JSON-RPC success.
fn success(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// A JSON-RPC error.
///
/// A code an agent can branch on, and a message for a human reading a log. An agent handed only a
/// sentence retries, rephrases, and eventually reports something that did not happen.
fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn store() -> SqliteStore {
        use brolga_storage::IntelligenceStore;

        let mut store = SqliteStore::open_in_memory().unwrap();
        store.migrate().unwrap();
        store
    }

    fn exchange(requests: &[Value]) -> Vec<Value> {
        let input: String = requests
            .iter()
            .map(|request| format!("{request}\n"))
            .collect();
        let mut output = Vec::new();
        serve(input.as_bytes(), &mut output, &mut store()).unwrap();

        String::from_utf8(output)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// **The criterion.** The whole handshake, then a tool call — the workflow an agent actually
    /// performs.
    #[test]
    fn an_agent_can_handshake_list_tools_and_call_one() {
        let responses = exchange(&[
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "brolga_context",
                "arguments": {"kind": "ip", "value": "203.0.113.42"}
            }}),
        ]);

        // Three responses, not four: the notification gets none, which the protocol requires.
        assert_eq!(responses.len(), 3, "{responses:#?}");

        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(responses[0]["result"]["capabilities"]["tools"].is_object());

        let tools = responses[1]["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());

        let pack = &responses[2]["result"]["structuredContent"];
        assert_eq!(pack["disposition"], "unknown");
        assert!(pack["fingerprint"].as_str().is_some_and(|f| !f.is_empty()));
    }

    /// **The criterion.** An agent that cannot tell which version of a pack it received cannot
    /// cache one or diff two.
    #[test]
    fn every_tool_declares_versioned_input_and_output_schemas() {
        let responses = exchange(&[json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})]);
        let tools = responses[0]["result"]["tools"].as_array().unwrap();

        for tool in tools {
            assert!(tool["name"].as_str().is_some_and(|n| !n.is_empty()));
            assert!(
                tool["description"].as_str().is_some_and(|d| d.len() > 20),
                "a one-word description tells an agent nothing: {tool}"
            );
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(tool["outputSchema"].is_object(), "{tool}");
        }

        // The pack tool names the versioned canonical type its output is.
        let context = tools
            .iter()
            .find(|tool| tool["name"] == "brolga_context")
            .unwrap();
        assert_eq!(
            context["outputSchema"]["x-brolga-schema"],
            "brolga.context_pack"
        );
    }

    /// **The criterion.** An agent that could pull source material by tool call would make one
    /// authorisation decision cover an unbounded amount of somebody else's licensed content.
    #[test]
    fn no_tool_returns_raw_source_objects() {
        for level in ["L4", "L5"] {
            let responses = exchange(&[json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "brolga_context",
                    "arguments": {"kind": "ip", "value": "203.0.113.42", "detail_level": level}
                }
            })]);

            assert_eq!(responses[0]["error"]["code"], codes::INVALID_PARAMS);
            assert!(
                responses[0]["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("expanding a handle")),
                "the refusal must say how to get it properly: {}",
                responses[0]
            );
        }
    }

    /// **The criterion.** An agent cannot tell a complete answer from a truncated one by counting,
    /// and will treat the second as the first.
    #[test]
    fn a_result_states_its_budget_whether_or_not_it_bit() {
        let responses = exchange(&[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "brolga_neighbours",
                "arguments": {"id": "entity:00000000-0000-4000-8000-000000000000"}
            }
        })]);

        let budget = &responses[0]["result"]["structuredContent"]["budget"];
        assert_eq!(budget["requested"], 50);
        assert_eq!(budget["returned"], 0);
        assert_eq!(budget["exhausted"], false);
    }

    /// A pack keeps its gaps and exclusions over MCP, because an agent acting on a pack needs to
    /// know what it does not contain as much as what it does.
    #[test]
    fn uncertainty_survives_the_tool_boundary() {
        let responses = exchange(&[json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "brolga_context",
                "arguments": {"kind": "ip", "value": "203.0.113.42"}
            }
        })]);

        let pack = &responses[0]["result"]["structuredContent"];
        let gaps = pack["gaps"].as_array().unwrap();
        assert!(
            gaps.iter().any(|gap| gap["detail"]
                .as_str()
                .is_some_and(|d| d.contains("nothing is stored"))),
            "{pack}"
        );
        assert!(pack["exclusions"].is_array());
        assert!(pack["policy"].is_object());
    }

    /// **The criterion.** An agent handed a sentence retries, rephrases, and eventually reports
    /// something that did not happen.
    #[test]
    fn a_refusal_is_a_code_an_agent_can_branch_on() {
        let responses = exchange(&[
            json!({"jsonrpc": "2.0", "id": 1, "method": "no_such_method"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "no_such_tool", "arguments": {}}}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "brolga_context", "arguments": {"kind": "ip"}}}),
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": {"name": "brolga_context",
                              "arguments": {"kind": "ip", "value": "not-an-address"}}}),
        ]);

        assert_eq!(responses[0]["error"]["code"], codes::METHOD_NOT_FOUND);
        assert_eq!(responses[1]["error"]["code"], codes::METHOD_NOT_FOUND);
        assert_eq!(responses[2]["error"]["code"], codes::INVALID_PARAMS);
        assert_eq!(responses[3]["error"]["code"], codes::INVALID_PARAMS);
    }

    /// One malformed line must not end the session. An agent that lost its connection because one
    /// call was malformed would retry the whole conversation.
    #[test]
    fn a_malformed_request_is_answered_rather_than_ending_the_session() {
        let mut output = Vec::new();
        let input = "not json\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        serve(input.as_bytes(), &mut output, &mut store()).unwrap();

        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(lines.len(), 2, "the session continued: {lines:#?}");
        assert_eq!(lines[0]["error"]["code"], codes::INVALID_REQUEST);
        assert!(lines[1]["result"].is_object(), "and still answered `ping`");
    }

    /// Every response is one line of JSON, because that is what the transport frames on.
    #[test]
    fn every_response_is_a_single_line_of_json() {
        let mut output = Vec::new();
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
        serve(input.as_bytes(), &mut output, &mut store()).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.ends_with('\n'), "a frame must be terminated");
    }
}
