use crate::store::{Flow, Headers, Message, Store};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

#[derive(Serialize)]
pub struct Difference {
    pub method: String,
    pub url: String,
    pub current_id: Option<u64>,
    pub other_id: Option<u64>,
    pub result: &'static str,
    pub fields: Vec<&'static str>,
}
fn headers(headers: &Headers) -> Vec<(String, &str)> {
    let mut result: Vec<_> = headers
        .iter()
        .map(|[name, value]| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}
fn message(
    left: &Message,
    right: &Message,
    phase: &'static str,
    fields: &mut Vec<&'static str>,
) -> bool {
    if headers(&left.headers) != headers(&right.headers) {
        fields.push(if phase == "request" {
            "request headers"
        } else {
            "response headers"
        });
    }
    if headers(&left.trailers) != headers(&right.trailers) {
        fields.push(if phase == "request" {
            "request trailers"
        } else {
            "response trailers"
        });
    }
    if left.body.data != right.body.data || left.body.size != right.body.size {
        fields.push(if phase == "request" {
            "request body"
        } else {
            "response body"
        });
    }
    left.body.truncated || right.body.truncated || !left.body.complete || !right.body.complete
}
fn identity(flow: &Flow) -> (String, String) {
    (
        if flow.metadata.upstream_method.is_empty() {
            flow.method.clone()
        } else {
            flow.metadata.upstream_method.clone()
        },
        flow.upstream_url.clone(),
    )
}
pub fn flows(left: &Flow, right: &Flow) -> Difference {
    let (method, url) = identity(left);
    let mut fields = Vec::new();
    if identity(left) != identity(right) {
        fields.push("destination / method");
    }
    if left.status != right.status {
        fields.push("status");
    }
    if left.error != right.error {
        fields.push("error");
    }
    let mut unknown = message(&left.request, &right.request, "request", &mut fields);
    match (&left.response, &right.response) {
        (Some(left), Some(right)) => unknown |= message(left, right, "response", &mut fields),
        (None, None) => unknown = true,
        _ => fields.push("response availability"),
    }
    Difference {
        method,
        url,
        current_id: Some(left.id),
        other_id: Some(right.id),
        result: if !fields.is_empty() {
            "changed"
        } else if unknown {
            "unknown"
        } else {
            "equal"
        },
        fields,
    }
}
pub fn sessions(current: &Store, other: &Store) -> Vec<Difference> {
    let mut groups: BTreeMap<_, VecDeque<_>> = BTreeMap::new();
    for flow in &other.flows {
        groups.entry(identity(flow)).or_default().push_back(flow);
    }
    let mut differences = Vec::new();
    for flow in &current.flows {
        let (method, url) = identity(flow);
        if let Some(other) = groups
            .get_mut(&(method.clone(), url.clone()))
            .and_then(VecDeque::pop_front)
        {
            differences.push(flows(flow, other));
        } else {
            differences.push(Difference {
                method,
                url,
                current_id: Some(flow.id),
                other_id: None,
                result: "added",
                fields: Vec::new(),
            });
        }
    }
    for queue in groups.values() {
        for flow in queue {
            let (method, url) = identity(flow);
            differences.push(Difference {
                method,
                url,
                current_id: None,
                other_id: Some(flow.id),
                result: "removed",
                fields: Vec::new(),
            });
        }
    }
    differences
}
