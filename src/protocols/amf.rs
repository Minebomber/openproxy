use super::{Budget, Cursor, Format, NODES};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

#[derive(Clone)]
struct Trait {
    class: String,
    dynamic: bool,
    names: Vec<String>,
}

struct Reader<'a, 'b> {
    cursor: Cursor<'a>,
    budget: &'b mut Budget,
    strings: Vec<String>,
    traits: Vec<Trait>,
    objects0: usize,
    objects3: usize,
}

pub(super) fn decode(data: &[u8], format: Format, budget: &mut Budget) -> Result<Value> {
    let mut reader = Reader {
        cursor: Cursor::new(data),
        budget,
        strings: Vec::new(),
        traits: Vec::new(),
        objects0: 0,
        objects3: 0,
    };
    let value = match format {
        Format::AmfPacket => reader.packet()?,
        Format::Amf0 | Format::Amf3 => {
            let mut values = Vec::new();
            while reader.cursor.position < data.len() {
                values.push(if matches!(format, Format::Amf0) {
                    reader.amf0(0)?
                } else {
                    reader.amf3(0)?
                });
            }
            json!(values)
        }
        _ => unreachable!(),
    };
    ensure!(
        reader.cursor.position == data.len(),
        "trailing AMF packet bytes"
    );
    Ok(value)
}

impl Reader<'_, '_> {
    fn text(&mut self, len: usize) -> Result<String> {
        let value = std::str::from_utf8(self.cursor.take(len)?).context("invalid AMF UTF-8")?;
        self.budget.text(value)
    }
    fn short(&mut self) -> Result<String> {
        let len = self.cursor.u16()? as usize;
        self.text(len)
    }
    fn long(&mut self) -> Result<String> {
        let len = self.cursor.u32()? as usize;
        self.text(len)
    }
    fn u29(&mut self) -> Result<u32> {
        let mut n = 0;
        for _ in 0..3 {
            let byte = self.cursor.u8()?;
            n = (n << 7) | (byte & 127) as u32;
            if byte < 128 {
                return Ok(n);
            }
        }
        Ok((n << 8) | self.cursor.u8()? as u32)
    }
    fn string3(&mut self) -> Result<String> {
        let n = self.u29()?;
        if n & 1 == 0 {
            return self.budget.text(
                self.strings
                    .get((n >> 1) as usize)
                    .context("invalid AMF3 string reference")?,
            );
        }
        let text = self.text((n >> 1) as usize)?;
        if !text.is_empty() {
            ensure!(self.strings.len() < NODES, "too many AMF3 strings");
            self.strings.push(text.clone());
        }
        Ok(text)
    }
    fn reference(&self, index: usize, v3: bool) -> Result<Value> {
        ensure!(
            index < if v3 { self.objects3 } else { self.objects0 },
            "invalid AMF object reference"
        );
        Ok(json!({"reference": index, "encoding": if v3 { "amf3" } else { "amf0" }}))
    }
    fn object_id(&mut self, v3: bool) -> Result<usize> {
        let count = if v3 {
            &mut self.objects3
        } else {
            &mut self.objects0
        };
        ensure!(*count < NODES, "too many AMF objects");
        let id = *count;
        *count += 1;
        Ok(id)
    }
    fn properties0(&mut self, depth: usize) -> Result<Value> {
        let mut properties = Vec::new();
        loop {
            let name = self.short()?;
            if name.is_empty() && self.cursor.data.get(self.cursor.position) == Some(&9) {
                self.cursor.u8()?;
                break;
            }
            properties.push(json!({"name": name, "value": self.amf0(depth + 1)?}));
        }
        Ok(json!(properties))
    }
    fn amf0(&mut self, depth: usize) -> Result<Value> {
        self.budget.node(depth)?;
        Ok(match self.cursor.u8()? {
            0 => self.cursor.f64()?,
            1 => json!(self.cursor.u8()? != 0),
            2 => json!(self.short()?),
            marker @ (3 | 8 | 16) => {
                let id = self.object_id(false)?;
                let class = if marker == 16 {
                    Some(self.short()?)
                } else {
                    None
                };
                let declared_count = if marker == 8 {
                    Some(self.cursor.u32()?)
                } else {
                    None
                };
                json!({"type": if marker == 8 { "ecma_array" } else { "object" }, "id": id, "encoding": "amf0", "class": class, "declared_count": declared_count, "properties": self.properties0(depth)?})
            }
            5 => Value::Null,
            6 => json!({"type": "undefined"}),
            7 => {
                let index = self.cursor.u16()? as usize;
                self.reference(index, false)?
            }
            10 => {
                let id = self.object_id(false)?;
                let count = self.cursor.u32()? as usize;
                ensure!(count <= self.budget.nodes, "AMF array exceeds value limit");
                let mut values = Vec::new();
                for _ in 0..count {
                    values.push(self.amf0(depth + 1)?);
                }
                json!({"type": "array", "id": id, "encoding": "amf0", "values": values})
            }
            11 => {
                let date = self.cursor.f64()?;
                let zone = self.cursor.u16()? as i16;
                json!({"type": "date", "milliseconds": date, "reserved_timezone": zone})
            }
            12 => json!(self.long()?),
            13 => json!({"type": "unsupported"}),
            15 => json!({"type": "xml", "text": self.long()?}),
            17 => self.amf3(depth + 1)?,
            marker => bail!("unsupported or unexpected AMF0 marker 0x{marker:02x}"),
        })
    }
    fn amf3(&mut self, depth: usize) -> Result<Value> {
        self.budget.node(depth)?;
        let marker = self.cursor.u8()?;
        Ok(match marker {
            0 => json!({"type": "undefined"}),
            1 => Value::Null,
            2 => json!(false),
            3 => json!(true),
            4 => {
                let n = self.u29()? as i32;
                json!(if n & 0x10000000 != 0 {
                    n - 0x20000000
                } else {
                    n
                })
            }
            5 => self.cursor.f64()?,
            6 => json!(self.string3()?),
            7..=17 => {
                let n = self.u29()?;
                if n & 1 == 0 {
                    return self.reference((n >> 1) as usize, true);
                }
                let id = self.object_id(true)?;
                match marker {
                    7 | 11 => {
                        json!({"type": if marker == 7 { "xml_document" } else { "xml" }, "id": id, "text": self.text((n >> 1) as usize)?})
                    }
                    8 => json!({"type": "date", "id": id, "milliseconds": self.cursor.f64()?}),
                    9 => {
                        let count = (n >> 1) as usize;
                        ensure!(count <= self.budget.nodes, "AMF array exceeds value limit");
                        let properties = self.properties3(depth)?;
                        let mut values = Vec::new();
                        for _ in 0..count {
                            values.push(self.amf3(depth + 1)?);
                        }
                        json!({"type": "array", "id": id, "properties": properties, "values": values})
                    }
                    10 => self.object3(n, id, depth)?,
                    12 => {
                        let bytes = self.cursor.take((n >> 1) as usize)?;
                        json!({"type": "byte_array", "id": id, "base64": STANDARD.encode(bytes)})
                    }
                    13..=16 => {
                        let count = (n >> 1) as usize;
                        ensure!(count <= self.budget.nodes, "AMF vector exceeds value limit");
                        let fixed = self.cursor.u8()? != 0;
                        let class = if marker == 16 {
                            Some(self.string3()?)
                        } else {
                            None
                        };
                        let mut values = Vec::new();
                        for _ in 0..count {
                            self.budget.node(depth + 1)?;
                            values.push(match marker {
                                13 => json!(self.cursor.u32()? as i32),
                                14 => json!(self.cursor.u32()?),
                                15 => self.cursor.f64()?,
                                _ => self.amf3(depth + 1)?,
                            });
                        }
                        json!({"type": match marker { 13 => "vector_int", 14 => "vector_uint", 15 => "vector_double", _ => "vector_object" }, "id": id, "fixed": fixed, "class": class, "values": values})
                    }
                    17 => {
                        let count = (n >> 1) as usize;
                        ensure!(
                            count <= self.budget.nodes / 2,
                            "AMF dictionary exceeds value limit"
                        );
                        let weak = self.cursor.u8()? != 0;
                        let mut entries = Vec::new();
                        for _ in 0..count {
                            entries.push(json!({"key": self.amf3(depth + 1)?, "value": self.amf3(depth + 1)?}));
                        }
                        json!({"type": "dictionary", "id": id, "weak_keys": weak, "entries": entries})
                    }
                    _ => unreachable!(),
                }
            }
            _ => bail!("unsupported AMF3 marker 0x{marker:02x}"),
        })
    }
    fn properties3(&mut self, depth: usize) -> Result<Value> {
        let mut properties = Vec::new();
        loop {
            let name = self.string3()?;
            if name.is_empty() {
                break;
            }
            properties.push(json!({"name": name, "value": self.amf3(depth + 1)?}));
        }
        Ok(json!(properties))
    }
    fn object3(&mut self, n: u32, id: usize, depth: usize) -> Result<Value> {
        let traits = if n & 2 == 0 {
            self.traits
                .get((n >> 2) as usize)
                .context("invalid AMF3 trait reference")?
                .clone()
        } else {
            ensure!(
                n & 4 == 0,
                "AMF3 externalizable objects need a class-specific decoder and are unsupported"
            );
            let count = (n >> 4) as usize;
            ensure!(
                count <= self.budget.nodes && self.traits.len() < NODES,
                "AMF traits exceed limit"
            );
            let class = self.string3()?;
            let mut names = Vec::new();
            for _ in 0..count {
                names.push(self.string3()?);
            }
            let traits = Trait {
                class,
                dynamic: n & 8 != 0,
                names,
            };
            self.traits.push(traits.clone());
            traits
        };
        let class = self.budget.text(&traits.class)?;
        let mut properties = Vec::new();
        for name in traits.names {
            let name = self.budget.text(&name)?;
            properties.push(json!({"name": name, "value": self.amf3(depth + 1)?}));
        }
        let dynamic = if traits.dynamic {
            self.properties3(depth)?
        } else {
            json!([])
        };
        Ok(
            json!({"type": "object", "id": id, "class": class, "sealed": properties, "dynamic": dynamic}),
        )
    }
    fn reset(&mut self) {
        self.strings.clear();
        self.traits.clear();
        self.objects0 = 0;
        self.objects3 = 0;
    }
    fn packet_value(&mut self) -> Result<Value> {
        let length = self.cursor.u32()?;
        let start = self.cursor.position;
        self.reset();
        let value = self.amf0(0)?;
        ensure!(
            length == u32::MAX || self.cursor.position - start == length as usize,
            "AMF packet value length does not match its declared length"
        );
        Ok(value)
    }
    fn packet(&mut self) -> Result<Value> {
        let version = self.cursor.u16()?;
        ensure!(
            version == 0 || version == 3,
            "unsupported AMF packet version"
        );
        let count = self.cursor.u16()? as usize;
        ensure!(count <= self.budget.nodes, "too many AMF packet headers");
        let mut headers = Vec::new();
        for _ in 0..count {
            let name = self.short()?;
            let required = self.cursor.u8()? != 0;
            headers.push(
                json!({"name": name, "must_understand": required, "value": self.packet_value()?}),
            );
        }
        let count = self.cursor.u16()? as usize;
        ensure!(count <= self.budget.nodes, "too many AMF packet messages");
        let mut messages = Vec::new();
        for _ in 0..count {
            let target = self.short()?;
            let response = self.short()?;
            messages.push(
                json!({"target": target, "response": response, "value": self.packet_value()?}),
            );
        }
        Ok(
            json!({"version": version, "headers": headers, "messages": messages, "note": "Object references use indices to prevent cycle expansion. Each externalizable AMF3 class must have its own decoder."}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amf0_objects_cycles_and_amf3_switch() {
        let bytes = [
            3, 0, 4, b's', b'e', b'l', b'f', 7, 0, 0, 0, 0, 9, 17, 4, 255, 255, 255, 255,
        ];
        let decoded = decode(&bytes, Format::Amf0, &mut Budget::default()).unwrap();
        assert_eq!(decoded[0]["properties"][0]["value"]["reference"], 0);
        assert_eq!(decoded[1], -1);
    }
    #[test]
    fn amf3_strings_traits_arrays_and_vectors() {
        let bytes = [
            6, 5, b'h', b'i', 6, 0, 10, 0x13, 1, 3, b'x', 4, 42, 10, 1, 4, 43, 13, 3, 1, 0xff,
            0xff, 0xff, 0xff,
        ];
        let decoded = decode(&bytes, Format::Amf3, &mut Budget::default()).unwrap();
        assert_eq!(decoded[1], "hi");
        assert_eq!(decoded[2]["sealed"][0]["value"], 42);
        assert_eq!(decoded[3]["sealed"][0]["value"], 43);
        assert_eq!(decoded[4]["values"][0], -1);
        assert!(decode(&[10, 7, 1], Format::Amf3, &mut Budget::default()).is_err());
        assert!(decode(&[6, 2], Format::Amf3, &mut Budget::default()).is_err());
    }
    #[test]
    fn packets_reset_references_and_check_lengths() {
        let packet = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 5];
        assert_eq!(
            decode(&packet, Format::AmfPacket, &mut Budget::default()).unwrap()["messages"][0]["value"],
            Value::Null
        );
        let mut invalid = packet;
        invalid[13] = 2;
        assert!(decode(&invalid, Format::AmfPacket, &mut Budget::default()).is_err());
        assert!(
            decode(
                &[10, 0xff, 0xff, 0xff, 0xff],
                Format::Amf0,
                &mut Budget::default()
            )
            .is_err()
        );
        assert!(
            decode(
                &[3, 0, 1, b'a', 3].repeat(40),
                Format::Amf0,
                &mut Budget::default()
            )
            .is_err()
        );
    }
}
