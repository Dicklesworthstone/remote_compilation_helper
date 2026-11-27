//! Prepare a complete bounded request before connecting to the edge. Oversized
//! or non-Unicode environment values may still permit a names-only observation.
use super::{MAX_REQUEST_BYTES, json_string};
use std::ffi::OsString;

pub(super) struct RequestFrame {
    pub(super) text: String,
    pub(super) live: bool,
}

pub(super) fn prepare<I>(
    args: &[String],
    cwd: &str,
    environment: impl Fn() -> I,
) -> Option<RequestFrame>
where
    I: Iterator<Item = (OsString, OsString)>,
{
    for live in [true, false] {
        if let Some(text) = encode(args, cwd, &environment, live) {
            return Some(RequestFrame { text, live });
        }
    }
    None
}

fn push(frame: &mut String, value: &str) -> Option<()> {
    (value.len() <= MAX_REQUEST_BYTES - frame.len()).then_some(())?;
    frame.push_str(value);
    Some(())
}

fn quoted(frame: &mut String, value: &str) -> Option<()> {
    // Check the unescaped length first. A large value must not allocate a
    // temporary escaped copy just to discover that neither will fit.
    let remaining = (MAX_REQUEST_BYTES - frame.len()).checked_sub(2)?;
    (value.len() <= remaining).then_some(())?;
    let extra: usize = value
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' => 1,
            0x00..=0x1f => 5,
            _ => 0,
        })
        .sum();
    (extra <= remaining - value.len()).then_some(())?;
    if extra == 0 {
        frame.push('"');
        frame.push_str(value);
        frame.push('"');
        Some(())
    } else {
        push(frame, &json_string(value))
    }
}

fn encode<I>(args: &[String], cwd: &str, environment: &impl Fn() -> I, live: bool) -> Option<String>
where
    I: Iterator<Item = (OsString, OsString)>,
{
    let mut frame = String::from(if live {
        "{\"kind\":\"rustc-request\",\"argv\":["
    } else {
        "{\"kind\":\"consult\",\"argv\":["
    });
    for (index, arg) in args.iter().enumerate() {
        if index != 0 {
            push(&mut frame, ",")?;
        }
        quoted(&mut frame, arg)?;
    }
    push(&mut frame, "],\"cwd\":")?;
    quoted(&mut frame, cwd)?;
    let env_field = if live {
        ",\"env\":["
    } else {
        ",\"env_names\":["
    };
    push(&mut frame, env_field)?;
    let mut first = true;
    for (name, value) in environment() {
        let name = if live {
            name.to_str()?
        } else {
            let Some(name) = name
                .to_str()
                .filter(|name| name.starts_with("CARGO") || name.starts_with("RUSTC"))
            else {
                continue;
            };
            name
        };
        if !first {
            push(&mut frame, ",")?;
        }
        first = false;
        if live {
            push(&mut frame, "[")?;
            quoted(&mut frame, name)?;
            push(&mut frame, ",")?;
            quoted(&mut frame, value.to_str()?)?;
            push(&mut frame, "]")?;
        } else {
            quoted(&mut frame, name)?;
        }
    }
    let end = if live {
        "],\"wait_for_inflight\":true,\"remote_protocol\":1,\"metadata_protocol\":1}"
    } else {
        "]}"
    };
    push(&mut frame, end)?;
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply_json;

    #[test]
    fn full_frame_includes_exact_values_and_shadow_omits_them() {
        let args = ["rustc".to_owned(), "--cfg=π\n\"\\".to_owned()];
        let env = || [("CARGO_FOO".into(), "secret\nvalue".into())].into_iter();
        let live = prepare(&args, "/work", env).unwrap();
        assert!(live.live);
        let reply = reply_json::parse(&live.text).unwrap();
        let argv = reply.get("argv").unwrap().as_array().unwrap();
        assert_eq!(argv[1].as_str(), Some(args[1].as_str()));
        let vars = reply.get("env").unwrap().as_array().unwrap();
        let pair = vars[0].as_array().unwrap();
        assert_eq!(pair[1].as_str(), Some("secret\nvalue"));

        let huge = || [("CARGO_FOO".into(), "x".repeat(MAX_REQUEST_BYTES).into())].into_iter();
        let shadow = prepare(&args, "/work", huge).unwrap();
        assert!(!shadow.live);
        let reply = reply_json::parse(&shadow.text).unwrap();
        assert!(reply.get("env").is_none());
        let names = reply.get("env_names").unwrap().as_array().unwrap();
        assert_eq!(names[0].as_str(), Some("CARGO_FOO"));
    }

    #[test]
    fn a_non_unicode_value_permits_only_a_names_only_observation() {
        use std::os::unix::ffi::OsStringExt;

        let env = || {
            [
                ("RUSTC_DATA".into(), OsString::from_vec(vec![0xff])),
                (OsString::from_vec(vec![0xff]), "other".into()),
            ]
            .into_iter()
        };
        let shadow = prepare(&[], "/", env).unwrap();
        assert!(!shadow.live);
        let reply = reply_json::parse(&shadow.text).unwrap();
        let names = reply.get("env_names").unwrap().as_array().unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), Some("RUSTC_DATA"));
    }

    #[test]
    fn exact_limit_uses_wire_bytes_for_both_request_kinds() {
        let empty = || std::iter::empty::<(OsString, OsString)>();
        let huge = || [("RUSTC_TEST".into(), "x".repeat(MAX_REQUEST_BYTES).into())].into_iter();
        let live_overhead = prepare(&[String::new()], "/", empty).unwrap().text.len();
        let args = ["a".repeat(MAX_REQUEST_BYTES - live_overhead)];
        let live = prepare(&args, "/", empty).unwrap();
        assert!(live.live);
        assert_eq!(live.text.len(), MAX_REQUEST_BYTES);

        let shadow_overhead = prepare(&[String::new()], "/", huge).unwrap().text.len();
        let mut args = ["a".repeat(MAX_REQUEST_BYTES - shadow_overhead - 6)];
        args[0].push('\0'); // Encoded as six ASCII bytes.
        let shadow = prepare(&args, "/", huge).unwrap();
        assert!(!shadow.live);
        assert_eq!(shadow.text.len(), MAX_REQUEST_BYTES);
        args[0].push('x');
        assert!(prepare(&args, "/", huge).is_none());
        let name = "CARGO".repeat(MAX_REQUEST_BYTES / 5 + 1);
        let huge_names = || [(name.clone().into(), "".into())].into_iter();
        assert!(prepare(&[], "/", huge_names).is_none());
    }
}
