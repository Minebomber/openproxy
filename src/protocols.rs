mod amf;

use crate::store::Message;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MessageDescriptor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{Read, Write};

pub const INPUT_LIMIT: usize = 1024 * 1024;
const OUTPUT_LIMIT: usize = 4 * INPUT_LIMIT;
const NODES: usize = 4096;
const DEPTH: usize = 32;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Protobuf,
    Grpc,
    Amf0,
    Amf3,
    AmfPacket,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decode {
    pub direction: Direction,
    #[serde(default)]
    pub original: bool,
    pub format: Format,
    pub descriptor: Option<String>,
    pub message_name: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

pub fn selected(
    flow: &crate::store::Flow,
    direction: Direction,
    original: bool,
) -> Result<&Message> {
    match (direction, original) {
        (Direction::Request, false) => Some(&flow.request),
        (Direction::Response, false) => flow.response.as_ref(),
        (Direction::Request, true) => flow.metadata.original_request.as_ref(),
        (Direction::Response, true) => flow.metadata.original_response.as_ref(),
    }
    .context("selected message is not available")
}

pub fn header<'a>(message: &'a Message, name: &str) -> &'a str {
    message
        .headers
        .iter()
        .find(|h| h[0].eq_ignore_ascii_case(name))
        .map_or("", |h| &h[1])
}

fn inflate(data: &[u8], encoding: &str) -> Result<Vec<u8>> {
    ensure!(data.len() <= INPUT_LIMIT, "decoder input exceeds 1 MiB");
    let mut output = Vec::new();
    match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "identity" => output.extend_from_slice(data),
        "gzip" => {
            flate2::read::MultiGzDecoder::new(data)
                .take(INPUT_LIMIT as u64 + 1)
                .read_to_end(&mut output)?;
        }
        "deflate" => {
            flate2::read::ZlibDecoder::new(data)
                .take(INPUT_LIMIT as u64 + 1)
                .read_to_end(&mut output)?;
        }
        other => bail!("unsupported content encoding: {other}"),
    }
    ensure!(output.len() <= INPUT_LIMIT, "decoded input exceeds 1 MiB");
    Ok(output)
}

pub fn body_bytes(message: &Message) -> Result<Vec<u8>> {
    let encoding = message
        .headers
        .iter()
        .filter(|h| h[0].eq_ignore_ascii_case("content-encoding"))
        .map(|h| h[1].as_str())
        .collect::<Vec<_>>()
        .join(",");
    inflate(&message.body.data, &encoding)
}

pub fn decode(message: &Message, options: Decode) -> Result<Value> {
    let complete = message.body.complete && !message.body.truncated;
    let data = body_bytes(message).context(if complete {
        "body decoding failed"
    } else {
        "incomplete capture cannot be decompressed"
    })?;
    let schema = match (options.descriptor, options.message_name) {
        (None, None) => None,
        (Some(encoded), Some(name)) => {
            ensure!(
                encoded.len() <= INPUT_LIMIT.div_ceil(3) * 4 && name.len() <= 1024,
                "descriptor or message name exceeds limit"
            );
            let bytes = STANDARD
                .decode(encoded)
                .context("descriptor must be a base64 FileDescriptorSet")?;
            ensure!(bytes.len() <= INPUT_LIMIT, "descriptor exceeds 1 MiB");
            let pool = DescriptorPool::decode(bytes.as_slice())
                .context("invalid FileDescriptorSet; include dependencies")?;
            Some(
                pool.get_message_by_name(name.trim_start_matches('.'))
                    .context("message name was not found in the descriptor")?,
            )
        }
        _ => bail!("provide both a FileDescriptorSet and its fully qualified message name"),
    };
    let mut budget = Budget::default();
    let result = match options.format {
        Format::Protobuf => protobuf(&data, schema.as_ref(), &mut budget),
        Format::Grpc => grpc(
            &data,
            schema.as_ref(),
            header(message, "grpc-encoding"),
            complete,
            &mut budget,
        ),
        Format::Amf0 | Format::Amf3 | Format::AmfPacket => {
            ensure!(schema.is_none(), "schemas apply to protobuf and gRPC only");
            amf::decode(&data, options.format, &mut budget)
        }
    }
    .with_context(|| {
        if complete {
            "protocol decoding failed"
        } else {
            "capture is incomplete; missing bytes may prevent decoding"
        }
    })?;
    bounded_json(&result)?;
    Ok(
        json!({ "format": options.format, "capture_complete": complete, "warning": (!complete).then_some("Only a captured prefix is available; this is not a complete-message validation."), "value": result }),
    )
}

struct LimitedWriter(Vec<u8>);
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + bytes.len() > OUTPUT_LIMIT {
            return Err(std::io::Error::other("decoder output exceeds 4 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut writer = LimitedWriter(Vec::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

struct Budget {
    nodes: usize,
    wire_nodes: usize,
    bytes: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            nodes: NODES,
            wire_nodes: NODES,
            bytes: OUTPUT_LIMIT,
        }
    }
}
impl Budget {
    fn wire_node(&mut self, depth: usize) -> Result<()> {
        ensure!(depth <= DEPTH, "decoder nesting exceeds 32 levels");
        ensure!(self.wire_nodes > 0, "decoder wire exceeds 4096 values");
        self.wire_nodes -= 1;
        Ok(())
    }
    fn node(&mut self, depth: usize) -> Result<()> {
        ensure!(depth <= DEPTH, "decoder nesting exceeds 32 levels");
        ensure!(self.nodes > 0, "decoder exceeds 4096 values");
        self.nodes -= 1;
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<String> {
        ensure!(value.len() <= self.bytes, "decoder output exceeds 4 MiB");
        self.bytes -= value.len();
        Ok(value.to_owned())
    }
    fn check(&mut self, value: &Value, depth: usize) -> Result<()> {
        self.node(depth)?;
        match value {
            Value::Array(values) => {
                for value in values {
                    self.check(value, depth + 1)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    self.check(value, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).context("length overflow")?;
        ensure!(
            end <= self.data.len(),
            "incomplete value at byte {}: need {len} bytes",
            self.position
        );
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn f64(&mut self) -> Result<Value> {
        let n = f64::from_be_bytes(self.take(8)?.try_into().unwrap());
        Ok(if n.is_finite() {
            json!(n)
        } else {
            json!({"number": if n.is_nan() { "NaN" } else if n.is_sign_positive() { "Infinity" } else { "-Infinity" } })
        })
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let byte = self.u8()?;
            ensure!(shift != 63 || byte <= 1, "protobuf varint overflow");
            value |= ((byte & 127) as u64) << shift;
            if byte < 128 {
                return Ok(value);
            }
        }
        bail!("protobuf varint overflow")
    }
}

fn protobuf(data: &[u8], schema: Option<&MessageDescriptor>, budget: &mut Budget) -> Result<Value> {
    if let Some(schema) = schema {
        wire_preflight(&mut Cursor::new(data), Some(schema), budget, 0, None)?;
        let message = DynamicMessage::decode(schema.clone(), data)?;
        let value: Value = serde_json::from_slice(&bounded_json(&message)?)?;
        budget.check(&value, 0)?;
        return Ok(json!({"message_name": schema.full_name(), "fields": value}));
    }
    let mut cursor = Cursor::new(data);
    let fields = raw_fields(&mut cursor, budget, 0, None)?;
    Ok(
        json!({"interpretation": "Wire types and field numbers only. Length-delimited bytes are ambiguous without a schema; integer signedness and packed fields are unknown.", "fields": fields}),
    )
}

// Validate unknown fields, nested messages, and packed values before DynamicMessage allocates memory for them.
fn wire_preflight(
    cursor: &mut Cursor<'_>,
    schema: Option<&MessageDescriptor>,
    budget: &mut Budget,
    depth: usize,
    group: Option<u64>,
) -> Result<()> {
    ensure!(depth <= DEPTH, "decoder nesting exceeds 32 levels");
    let any = schema.filter(|s| s.full_name() == "google.protobuf.Any");
    let mut type_url = None;
    let mut payload = None;
    let mut closed_group = false;
    while cursor.position < cursor.data.len() {
        budget.wire_node(depth)?;
        let key = cursor.varint()?;
        let number = key >> 3;
        ensure!(
            number > 0 && number <= 0x1fffffff,
            "invalid protobuf field number"
        );
        let field = schema.and_then(|s| s.get_field(number as u32));
        match key & 7 {
            0 => {
                cursor.varint()?;
            }
            1 => {
                cursor.take(8)?;
            }
            2 => {
                let length = usize::try_from(cursor.varint()?)?;
                let data = cursor.take(length)?;
                if any.is_some() {
                    if number == 1 {
                        type_url = Some(data);
                    }
                    if number == 2 {
                        payload = Some(data);
                    }
                }
                if let Some(field) = field {
                    match field.kind() {
                        Kind::Message(message) => wire_preflight(
                            &mut Cursor::new(data),
                            Some(&message),
                            budget,
                            depth + 1,
                            None,
                        )?,
                        Kind::String | Kind::Bytes => {}
                        kind if field.is_list() => {
                            let mut packed = Cursor::new(data);
                            while packed.position < data.len() {
                                budget.wire_node(depth + 1)?;
                                match kind {
                                    Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => {
                                        packed.take(8)?;
                                    }
                                    Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => {
                                        packed.take(4)?;
                                    }
                                    _ => {
                                        packed.varint()?;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            3 => {
                let nested = field.and_then(|f| match f.kind() {
                    Kind::Message(message) => Some(message),
                    _ => None,
                });
                wire_preflight(cursor, nested.as_ref(), budget, depth + 1, Some(number))?;
            }
            4 => {
                ensure!(group == Some(number), "unmatched protobuf end-group");
                closed_group = true;
                break;
            }
            5 => {
                cursor.take(4)?;
            }
            wire => bail!("invalid protobuf wire type {wire}"),
        }
    }
    ensure!(
        group.is_none() || closed_group,
        "unterminated protobuf group"
    );
    if let (Some(any), Some(type_url)) = (any, type_url) {
        let name = std::str::from_utf8(type_url)?
            .rsplit('/')
            .next()
            .unwrap_or_default();
        if let Some(message) = any.parent_pool().get_message_by_name(name) {
            wire_preflight(
                &mut Cursor::new(payload.unwrap_or_default()),
                Some(&message),
                budget,
                depth + 1,
                None,
            )?;
        }
    }
    Ok(())
}

fn raw_fields(
    cursor: &mut Cursor<'_>,
    budget: &mut Budget,
    depth: usize,
    group: Option<u64>,
) -> Result<Vec<Value>> {
    let mut fields = Vec::new();
    while cursor.position < cursor.data.len() {
        budget.node(depth)?;
        let key = cursor.varint()?;
        let number = key >> 3;
        let wire = key & 7;
        ensure!(
            number > 0 && number <= 0x1fffffff,
            "invalid protobuf field number"
        );
        if wire == 4 {
            ensure!(group == Some(number), "unmatched protobuf end-group");
            return Ok(fields);
        }
        let value = match wire {
            0 => json!(cursor.varint()?.to_string()),
            1 => json!(u64::from_le_bytes(cursor.take(8)?.try_into().unwrap()).to_string()),
            2 => {
                let n = usize::try_from(cursor.varint()?)?;
                json!({"base64": STANDARD.encode(cursor.take(n)?), "length": n})
            }
            3 => json!(raw_fields(cursor, budget, depth + 1, Some(number))?),
            5 => json!(u32::from_le_bytes(cursor.take(4)?.try_into().unwrap())),
            _ => bail!("invalid protobuf wire type {wire}"),
        };
        fields.push(json!({"number": number, "wire_type": wire, "value": value}));
    }
    ensure!(group.is_none(), "unterminated protobuf group");
    Ok(fields)
}

fn grpc(
    data: &[u8],
    schema: Option<&MessageDescriptor>,
    encoding: &str,
    complete: bool,
    budget: &mut Budget,
) -> Result<Value> {
    let mut cursor = Cursor::new(data);
    let mut messages = Vec::new();
    let mut incomplete = false;
    let mut decoded_total = 0;
    while cursor.position < data.len() {
        budget.node(0)?;
        if data.len() - cursor.position < 5 {
            incomplete = true;
            break;
        }
        let flag = cursor.u8()?;
        ensure!(flag <= 1, "invalid gRPC compressed flag");
        let len = cursor.u32()? as usize;
        if len > data.len() - cursor.position {
            incomplete = true;
            break;
        }
        let bytes = cursor.take(len)?;
        let decoded = if flag == 1 {
            ensure!(
                !encoding.is_empty() && encoding != "identity",
                "gRPC message is compressed without a grpc-encoding"
            );
            inflate(bytes, encoding)?
        } else {
            bytes.to_vec()
        };
        decoded_total += decoded.len();
        ensure!(
            decoded_total <= INPUT_LIMIT,
            "decoded gRPC messages exceed 1 MiB"
        );
        messages.push(json!({"compressed": flag == 1, "size": len, "decoded_size": decoded.len(), "value": protobuf(&decoded, schema, budget)?}));
    }
    ensure!(
        !incomplete || !complete,
        "complete capture contains a truncated gRPC envelope"
    );
    Ok(
        json!({"messages": messages, "incomplete_envelope": incomplete, "note": "This decoder reads only gRPC message envelopes. For grpc-status, read HTTP trailers. It cannot decode gRPC-Web framing."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(format: Format) -> Decode {
        Decode {
            direction: Direction::Request,
            original: false,
            format,
            descriptor: None,
            message_name: None,
        }
    }
    fn message(data: &[u8], complete: bool) -> Message {
        Message {
            body: crate::store::CapturedBody {
                data: data.to_vec(),
                size: data.len() as u64,
                complete,
                truncated: false,
            },
            ..Default::default()
        }
    }

    #[test]
    fn wire_numbers_are_preserved_without_guessing_a_schema() {
        let result = decode(
            &message(&[8, 150, 1, 18, 2, b'h', b'i'], true),
            options(Format::Protobuf),
        )
        .unwrap();
        assert_eq!(result["value"]["fields"][0]["number"], 1);
        assert_eq!(result["value"]["fields"][0]["value"], "150");
        assert_eq!(result["value"]["fields"][1]["value"]["base64"], "aGk=");
        let group = decode(&message(&[11, 16, 1, 12], true), options(Format::Protobuf)).unwrap();
        assert_eq!(group["value"]["fields"][0]["value"][0]["number"], 2);
        assert!(decode(&message(&[11, 20], true), options(Format::Protobuf)).is_err());
        assert!(decode(&message(&[11; 40], true), options(Format::Protobuf)).is_err());
        assert!(decode(&message(&[0], true), options(Format::Protobuf)).is_err());
        assert!(
            decode(
                &message(&[8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2], true),
                options(Format::Protobuf)
            )
            .is_err()
        );
    }
    #[test]
    fn grpc_distinguishes_prefix_from_invalid_complete_body() {
        let bytes = [0, 0, 0, 0, 2, 8, 1, 0, 0];
        let result = decode(&message(&bytes, false), options(Format::Grpc)).unwrap();
        assert_eq!(result["value"]["messages"].as_array().unwrap().len(), 1);
        assert_eq!(result["value"]["incomplete_envelope"], true);
        assert_eq!(result["capture_complete"], false);
        assert!(decode(&message(&bytes, true), options(Format::Grpc)).is_err());
    }
    #[test]
    fn explicit_descriptor_names_fields_and_decodes_gzip_grpc_messages() {
        use prost_reflect::{
            prost::Message as _,
            prost_types::{
                DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
                field_descriptor_proto::{Label, Type},
            },
        };
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("fixture.proto".into()),
                package: Some("fixture".into()),
                syntax: Some("proto3".into()),
                message_type: vec![DescriptorProto {
                    name: Some("Record".into()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("count".into()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Int32 as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("child".into()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".fixture.Record".into()),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("values".into()),
                            number: Some(3),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::Int32 as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let descriptor = STANDARD.encode(descriptors.encode_to_vec());
        let mut packed = vec![26];
        prost_reflect::prost::encoding::encode_varint((NODES + 1) as u64, &mut packed);
        packed.extend(vec![0; NODES + 1]);
        let mut nested = Vec::new();
        for _ in 0..DEPTH + 2 {
            let mut parent = vec![18];
            prost_reflect::prost::encoding::encode_varint(nested.len() as u64, &mut parent);
            parent.extend(nested);
            nested = parent;
        }
        for (data, expected) in [
            ([32, 1].repeat(NODES + 1), "4096"),
            (packed, "4096"),
            (nested, "32 levels"),
        ] {
            let mut opts = options(Format::Protobuf);
            opts.descriptor = Some(descriptor.clone());
            opts.message_name = Some("fixture.Record".into());
            let error = decode(&message(&data, true), opts).unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        let mut opts = options(Format::Protobuf);
        opts.descriptor = Some(descriptor.clone());
        opts.message_name = Some("fixture.Record".into());
        let value = decode(&message(&[26, 3, 1, 2, 3, 18, 2, 8, 9], true), opts).unwrap();
        assert_eq!(value["value"]["fields"]["values"], json!([1, 2, 3]));
        assert_eq!(value["value"]["fields"]["child"]["count"], 9);
        let mut opts = options(Format::Protobuf);
        opts.descriptor = Some(descriptor.clone());
        opts.message_name = Some("fixture.Record".into());
        let value = decode(&message(&[8, 42], true), opts).unwrap();
        assert_eq!(value["value"]["fields"]["count"], 42);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[8, 7]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut envelope = vec![1];
        envelope.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&compressed);
        let mut capture = message(&envelope, true);
        capture
            .headers
            .push(["grpc-encoding".into(), "gzip".into()]);
        let mut opts = options(Format::Grpc);
        opts.descriptor = Some(descriptor.clone());
        opts.message_name = Some("fixture.Record".into());
        let value = decode(&capture, opts).unwrap();
        assert_eq!(value["value"]["messages"][0]["value"]["fields"]["count"], 7);
        let mut opts = options(Format::Protobuf);
        opts.descriptor = Some(descriptor);
        opts.message_name = Some("fiction.Unknown".into());
        assert!(decode(&message(&[8, 42], true), opts).is_err());
    }
    #[test]
    fn parser_budgets_and_compression_are_enforced() {
        assert!(
            decode(
                &message(&[8, 1].repeat(NODES + 1), true),
                options(Format::Protobuf)
            )
            .is_err()
        );
        let mut compressed =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        compressed.write_all(&vec![0; INPUT_LIMIT + 1]).unwrap();
        assert!(inflate(&compressed.finish().unwrap(), "gzip").is_err());
        assert!(decode(&message(&[1, 0, 0, 0, 1, 0], true), options(Format::Grpc)).is_err());
    }

    #[test]
    fn any_payloads_cannot_evade_schema_nesting_budget() {
        use prost_reflect::{
            prost::Message as _,
            prost_types::{
                Any, DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
                field_descriptor_proto::{Label, Type},
            },
        };
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("any.proto".into()),
                package: Some("google.protobuf".into()),
                syntax: Some("proto3".into()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Any".into()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("type_url".into()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("value".into()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Bytes as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("Empty".into()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        let descriptor = STANDARD.encode(descriptors.encode_to_vec());
        let mut payload = Any {
            type_url: "type.googleapis.com/google.protobuf.Empty".into(),
            value: Vec::new(),
        }
        .encode_to_vec();
        let mut opts = options(Format::Protobuf);
        opts.descriptor = Some(descriptor.clone());
        opts.message_name = Some("google.protobuf.Any".into());
        assert!(decode(&message(&payload, true), opts).is_ok());
        for _ in 0..DEPTH + 2 {
            payload = Any {
                type_url: "type.googleapis.com/google.protobuf.Any".into(),
                value: payload,
            }
            .encode_to_vec();
        }
        let mut opts = options(Format::Protobuf);
        opts.descriptor = Some(descriptor);
        opts.message_name = Some("google.protobuf.Any".into());
        let error = decode(&message(&payload, true), opts).unwrap_err();
        assert!(format!("{error:#}").contains("32 levels"), "{error:#}");
    }
}
