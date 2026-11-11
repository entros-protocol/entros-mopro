use crate::MoproError;
use num_bigint::BigUint;
use serde_json::{Map, Value};

const SCALAR_MODULUS: &[u8] =
    b"21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn invalid(name: &str) -> MoproError {
    MoproError::CircomError(format!("Invalid circuit input: {name}"))
}

fn decimal(value: &Value, name: &str, limit: &BigUint) -> Result<String, MoproError> {
    let text = match value {
        Value::String(text) => Some(text.as_str()),
        Value::Array(values) if values.len() == 1 => values[0].as_str(),
        _ => None,
    }
    .ok_or_else(|| invalid(name))?;
    if text.is_empty()
        || text.len() > 78
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(invalid(name));
    }
    let integer = BigUint::parse_bytes(text.as_bytes(), 10).ok_or_else(|| invalid(name))?;
    if &integer >= limit {
        return Err(invalid(name));
    }
    Ok(text.to_owned())
}

fn fingerprint(value: &Value, name: &str) -> Result<Value, MoproError> {
    let values = value.as_array().ok_or_else(|| invalid(name))?;
    if values.len() != 256 {
        return Err(invalid(name));
    }
    values
        .iter()
        .map(|value| match value {
            Value::String(bit) if bit == "0" || bit == "1" => Ok(Value::String(bit.clone())),
            Value::Number(bit) if bit.as_u64().is_some_and(|bit| bit <= 1) => {
                Ok(Value::String(bit.to_string()))
            }
            _ => Err(invalid(name)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

pub(crate) fn normalize(json: &str, bound: bool) -> Result<String, MoproError> {
    let value: Value = serde_json::from_str(json).map_err(|_| invalid("JSON"))?;
    let object = value.as_object().ok_or_else(|| invalid("object"))?;
    if object.len() != if bound { 10 } else { 8 } {
        return Err(invalid("field count"));
    }
    let mut output = Map::new();
    for name in ["ft_new", "ft_prev"] {
        let value = object.get(name).ok_or_else(|| invalid(name))?;
        output.insert(name.to_owned(), fingerprint(value, name)?);
    }
    let field =
        BigUint::parse_bytes(SCALAR_MODULUS, 10).ok_or_else(|| invalid("scalar modulus"))?;
    let bits = BigUint::from(512u16);
    let limb = BigUint::from(1u8) << 128;
    let mut scalars = vec![
        ("salt_new", &field),
        ("salt_prev", &field),
        ("commitment_new", &field),
        ("commitment_prev", &field),
        ("threshold", &bits),
        ("min_distance", &bits),
    ];
    if bound {
        scalars.extend([("request_digest_hi", &limb), ("request_digest_lo", &limb)]);
    }
    // The witness adapter accepts only arrays of decimal strings.
    for (name, limit) in scalars {
        let value = object.get(name).ok_or_else(|| invalid(name))?;
        output.insert(
            name.to_owned(),
            Value::Array(vec![Value::String(decimal(value, name, limit)?)]),
        );
    }
    serde_json::to_string(&output).map_err(|_| invalid("serialization"))
}

pub(crate) fn validate_public_inputs(inputs: &[String], bound: bool) -> Result<(), MoproError> {
    if inputs.len() != if bound { 6 } else { 4 } {
        return Err(invalid("public input count"));
    }
    let field =
        BigUint::parse_bytes(SCALAR_MODULUS, 10).ok_or_else(|| invalid("scalar modulus"))?;
    let bounds = BigUint::from(512u16);
    let limb = BigUint::from(1u8) << 128;
    for (index, input) in inputs.iter().enumerate() {
        let limit = match index {
            0 | 1 => &field,
            2 | 3 => &bounds,
            _ => &limb,
        };
        decimal(&Value::String(input.clone()), "public input", limit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Value {
        serde_json::json!({
            "ft_new": vec![0; 256], "ft_prev": vec![1; 256],
            "salt_new": "1", "salt_prev": "2", "commitment_new": "3",
            "commitment_prev": "4", "threshold": "30", "min_distance": "3",
            "request_digest_hi": "5", "request_digest_lo": "6"
        })
    }

    #[test]
    fn normalizes_mobile_values_without_dropping_inputs() -> Result<(), Box<dyn std::error::Error>>
    {
        let parsed: Value = serde_json::from_str(&normalize(&valid().to_string(), true)?)?;
        assert_eq!(parsed["ft_new"][0], "0");
        assert_eq!(parsed["ft_prev"][255], "1");
        assert_eq!(parsed["commitment_new"], serde_json::json!(["3"]));
        assert_eq!(parsed["request_digest_hi"], serde_json::json!(["5"]));
        assert_eq!(normalize(&parsed.to_string(), true)?, parsed.to_string());
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_inputs() {
        for (name, value) in [
            (
                "commitment_new",
                Value::String(String::from_utf8_lossy(SCALAR_MODULUS).into_owned()),
            ),
            ("salt_new", serde_json::json!("-1")),
            ("salt_new", serde_json::json!("01")),
            ("salt_new", serde_json::json!(1)),
            ("threshold", serde_json::json!("512")),
            (
                "request_digest_hi",
                serde_json::json!("340282366920938463463374607431768211456"),
            ),
            ("request_digest_lo", serde_json::json!(["1", "2"])),
            ("ft_new", serde_json::json!([0, 1])),
            ("ft_prev", serde_json::json!(vec![2; 256])),
        ] {
            let mut input = valid();
            input[name] = value;
            assert!(normalize(&input.to_string(), true).is_err(), "{name}");
        }
        assert!(normalize(&valid().to_string(), false).is_err());
        assert!(normalize("invalid", true).is_err());
    }

    #[test]
    fn rejects_aliased_or_malformed_public_statements() {
        let valid = ["1", "2", "30", "3", "0", "0"].map(str::to_owned);
        assert!(validate_public_inputs(&valid, true).is_ok());
        assert!(validate_public_inputs(&valid[..4], false).is_ok());
        assert!(validate_public_inputs(&valid[..5], true).is_err());
        for (index, value) in [
            (
                0,
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            ),
            (1, "01"),
            (2, "512"),
            (3, "-1"),
            (4, "340282366920938463463374607431768211456"),
            (5, "+1"),
        ] {
            let mut changed = valid.clone();
            changed[index] = value.to_owned();
            assert!(validate_public_inputs(&changed, true).is_err());
        }
    }
}
