//! Judge keri-go's output with keriox — an implementation that did not generate
//! our vectors.
//!
//! keripy has already accepted these events, which matters, but keripy is also
//! where the conformance vectors came from. Agreement there partly reflects that
//! shared origin. keriox is independent Rust, written by different people from a
//! reading of the same specification, so this is the first judge whose agreement
//! is not circular.
//!
//! Upstream keriox, pinned by commit — deliberately not the copy embedded in the
//! mobile app, which is not known to be correct. If that copy and this package
//! were wrong in the same way, a test between them would say nothing.
//!
//!     go run ./interop | cargo run --manifest-path interop-keriox/Cargo.toml

use std::{convert::TryFrom, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use cesrox::{parse, parse_many};
use keri_core::{
    database::redb::RedbDatabase,
    event_message::signed_event_message::{Message, Notice},
    prefix::IdentifierPrefix,
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
        Processor,
    },
};
use said::SelfAddressingIdentifier;
use serde::Deserialize;
use std::str::FromStr;
use teliox::{
    database::{redb::RedbTelDatabase, EscrowDatabase as TelEscrowDb},
    processor::storage::TelEventStorage,
    tel::Tel,
};
use tempfile::NamedTempFile;

#[derive(Deserialize)]
struct Case {
    label: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    event_b64: String,
    #[serde(default)]
    message_b64: String,
    #[serde(default)]
    extra_b64: Vec<String>,
    #[serde(default)]
    skipped: String,
    #[serde(default)]
    issuer: String,
}

fn decode(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("case field is not base64")
}

fn main() {
    let cases: Vec<Case> =
        serde_json::from_reader(std::io::stdin()).expect("stdin is not the case list");

    let events_db_path = NamedTempFile::new().unwrap();
    let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let (not_bus, _escrows) = default_escrow_bus(events_db.clone(), EscrowConfig::default(), None);
    let processor = BasicProcessor::new(Arc::clone(&events_db), Some(not_bus));
    let storage = EventStorage::new(Arc::clone(&events_db));

    // The TEL needs the KEL beside it: a transaction event is only worth
    // anything because the issuer's key log anchors it, so teliox is given the
    // same key-event storage the processor above writes into.
    let tel_db_path = NamedTempFile::new().unwrap();
    let tel_db = Arc::new(RedbTelDatabase::new(tel_db_path.path()).unwrap());
    let tel = Tel::new(
        Arc::new(TelEventStorage::new(tel_db)),
        Arc::new(EventStorage::new(Arc::clone(&events_db))),
        None,
    );

    let (mut accepted, mut refused, mut skipped) = (0, 0, 0);

    for case in &cases {
        if !case.skipped.is_empty() {
            println!("  SKIPPED  {:30} {}", case.label, case.skipped);
            skipped += 1;
            continue;
        }
        // Transaction events go to teliox, which is a different surface from the
        // key-event processor. Running them through the wrong one to produce a
        // green line would be worse than reporting them untested.
        if case.kind == "tel" {
            match judge_tel(&tel, &processor, case) {
                Ok(detail) => {
                    println!("  accepted {:30} {}", case.label, detail);
                    accepted += 1;
                }
                Err(why) => {
                    println!("  REFUSED  {:30} {}", case.label, why);
                    refused += 1;
                }
            }
            continue;
        }
        // A whole key log as one stream. The messages carry no delimiter, so
        // keriox has to find each boundary itself from the version strings and
        // attachment counters. A framing error of one character misreads
        // everything after the first message — which validating them one at a
        // time cannot catch.
        if case.kind == "stream" {
            match judge_stream(&processor, &storage, case) {
                Ok(detail) => {
                    println!("  accepted {:30} {}", case.label, detail);
                    accepted += 1;
                }
                Err(why) => {
                    println!("  REFUSED  {:30} {}", case.label, why);
                    refused += 1;
                }
            }
            continue;
        }
        if case.kind == "credential" {
            match judge_credential(case) {
                Ok(detail) => {
                    println!("  accepted {:30} {}", case.label, detail);
                    accepted += 1;
                }
                Err(why) => {
                    println!("  REFUSED  {:30} {}", case.label, why);
                    refused += 1;
                }
            }
            continue;
        }
        if case.kind != "kel" && case.kind != "delegation" {
            println!(
                "  SKIPPED  {:30} kind {:?} is unknown",
                case.label, case.kind
            );
            skipped += 1;
            continue;
        }

        // Anything the event depends on goes in first: witness receipts, a
        // delegator's approval.
        let mut feed: Vec<Vec<u8>> = vec![decode(&case.message_b64)];
        for extra in &case.extra_b64 {
            feed.push(decode(extra));
        }

        let mut err: Option<String> = None;
        for raw in &feed {
            match parse(raw) {
                Ok((_, parsed)) => match Message::try_from(parsed) {
                    Ok(msg) => {
                        if let Err(e) = processor.process(&msg) {
                            // Not fatal on its own: a witnessed or delegated
                            // event is expected to be held until what it waits
                            // for arrives.
                            err = Some(format!("{e}"));
                        }
                    }
                    Err(e) => err = Some(format!("not a KERI message: {e}")),
                },
                Err(e) => err = Some(format!("not parseable as CESR: {e:?}")),
            }
        }

        // The identity comes from the MESSAGE, not the bare event. A bare event
        // carries no attachments, and cesrox is a stream parser: handed one, it
        // reports it cannot read it, which looks identical to a malformed event
        // and is not.
        let (id, want_sn) = match parse(&decode(&case.message_b64))
            .ok()
            .and_then(|(_, p)| Message::try_from(p).ok())
        {
            Some(Message::Notice(Notice::Event(e))) => (
                e.event_message.data.get_prefix(),
                e.event_message.data.get_sn(),
            ),
            _ => {
                let why = err.unwrap_or_else(|| "no diagnosis".into());
                println!(
                    "  REFUSED  {:30} keriox could not read it: {}",
                    case.label, why
                );
                refused += 1;
                continue;
            }
        };

        // Whether THIS event landed, not merely whether the identity exists.
        //
        // Checking only that a state is present reports success whenever any
        // earlier event was accepted — so a refused rotation reads as accepted
        // because the inception before it is still there. That mistake was made
        // here first and caught by a mutation that should have failed and did not.
        match storage.get_state(&id) {
            Some(state) if state.sn == want_sn => {
                println!("  accepted {:30} sn={} {}", case.label, state.sn, id);
                accepted += 1;
            }
            Some(state) => {
                println!(
                    "  REFUSED  {:30} the log is at sn={} but this event is sn={} — \
                     accepted events exist, this one is not among them",
                    case.label, state.sn, want_sn
                );
                refused += 1;
            }
            None => {
                let detail = err.unwrap_or_else(|| "nothing was established".into());
                println!("  REFUSED  {:30} {}", case.label, detail);
                refused += 1;
            }
        }
    }

    println!(
        "\n{accepted} accepted, {refused} refused, {skipped} skipped, out of {}",
        cases.len()
    );
    if refused > 0 {
        std::process::exit(1);
    }
}

/// Judge a transaction event with teliox.
///
/// The anchoring interaction goes into the key log first — a transaction event
/// asserts that something happened, and the issuer's key log is what makes that
/// assertion worth anything. Then the event itself, which carries the source
/// seal naming that interaction.
fn judge_tel<D, K>(
    tel: &Tel<D, K>,
    processor: &BasicProcessor<K>,
    case: &Case,
) -> Result<String, String>
where
    D: teliox::database::TelEventDatabase,
    K: keri_core::database::EventDatabase + 'static,
{
    if !case.message_b64.is_empty() {
        let raw = decode(&case.message_b64);
        let parsed = parse(&raw)
            .map_err(|e| format!("anchor is not CESR: {e:?}"))?
            .1;
        let msg = Message::try_from(parsed).map_err(|e| format!("anchor is not KERI: {e}"))?;
        processor
            .process(&msg)
            .map_err(|e| format!("the anchoring event was refused: {e}"))?;
    }

    let raw = decode(&case.event_b64);
    tel.parse_and_process_tel_stream(&raw)
        .map_err(|e| format!("{e}"))?;

    // Read the state back. A stream that parsed but established nothing is not
    // an acceptance, and reporting it as one is the mistake this harness has
    // already made once with key events.
    let sad: serde_json::Value =
        serde_json::from_slice(&raw[..find_json_end(&raw)]).map_err(|e| format!("{e}"))?;
    let ilk = sad["t"].as_str().unwrap_or("");
    let subject = sad["i"].as_str().unwrap_or("");

    if ilk == "vcp" {
        let id = IdentifierPrefix::from_str(subject).map_err(|e| format!("{e}"))?;
        return match tel.get_management_tel_state(&id) {
            Ok(Some(_)) => Ok(format!("registry live {subject}")),
            Ok(None) => Err("the registry was not established".into()),
            Err(e) => Err(format!("{e}")),
        };
    }

    let vc = SelfAddressingIdentifier::from_str(subject).map_err(|e| format!("{e}"))?;
    match tel.get_vc_state(&vc) {
        Ok(Some(state)) => Ok(format!("credential state is {state:?}")),
        Ok(None) => Err(format!("the credential has no state after a {ilk}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// A credential is a document: its identifier must be a digest of its contents.
fn judge_credential(case: &Case) -> Result<String, String> {
    let raw = decode(&case.event_b64);
    let sad: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| format!("{e}"))?;
    let said = sad["d"]
        .as_str()
        .ok_or("the credential has no identifier")?;
    let parsed = SelfAddressingIdentifier::from_str(said)
        .map_err(|e| format!("the identifier is not a digest keriox can read: {e}"))?;
    if !parsed.verify_binding(&blank_said(&raw, said)) {
        return Err(format!(
            "keriox does not accept {said} as a digest of this credential's contents"
        ));
    }
    Ok(format!("identifier verified {said}"))
}

/// Replace an identifier with the placeholder it was computed against.
///
/// A self-addressing identifier is the digest of the document with that field
/// blanked to the same width — not of the document without it, and not of the
/// document with the value present.
fn blank_said(raw: &[u8], said: &str) -> Vec<u8> {
    let dummy = "#".repeat(said.len());
    String::from_utf8_lossy(raw)
        .replacen(said, &dummy, 1)
        .into_bytes()
}

/// Find where the JSON body ends, so an attachment does not confuse the parser.
fn find_json_end(raw: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in raw.iter().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    raw.len()
}

/// Replay a whole key log handed over as one stream.
fn judge_stream<K>(
    processor: &BasicProcessor<K>,
    storage: &EventStorage<K>,
    case: &Case,
) -> Result<String, String>
where
    K: keri_core::database::EventDatabase + 'static,
{
    let raw = decode(&case.message_b64);
    let (rest, parsed) = parse_many(&raw).map_err(|e| format!("the stream is not CESR: {e:?}"))?;
    if !rest.is_empty() {
        return Err(format!(
            "{} bytes were left unparsed, so a message boundary was misread",
            rest.len()
        ));
    }
    let count = parsed.len();
    // Take the final event from the stream itself rather than a separate field.
    // The case's event_b64 holds a bare event with no attachments, and cesrox
    // is a stream parser — handed one it reports it cannot read it, which looks
    // identical to a malformed event and is not.
    let mut last: Option<(keri_core::prefix::IdentifierPrefix, u64)> = None;
    for p in parsed {
        let msg = Message::try_from(p).map_err(|e| format!("not a KERI message: {e}"))?;
        if let Message::Notice(Notice::Event(e)) = &msg {
            last = Some((
                e.event_message.data.get_prefix(),
                e.event_message.data.get_sn(),
            ));
        }
        processor
            .process(&msg)
            .map_err(|e| format!("a message in the stream was refused: {e}"))?;
    }

    // The last event must be what the log now stands at. A stream that parsed
    // but established less than it carries has been split wrongly somewhere.
    let (id, want_sn) = last.ok_or("the stream carried no key events")?;
    match storage.get_state(&id) {
        Some(state) if state.sn == want_sn => {
            Ok(format!("{count} messages replayed, sn={}", state.sn))
        }
        Some(state) => Err(format!(
            "the stream established up to sn={} but carries sn={}",
            state.sn, want_sn
        )),
        None => Err("nothing was established from the stream".into()),
    }
}
