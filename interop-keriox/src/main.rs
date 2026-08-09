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
use cesrox::parse;
use keri_core::{
    database::redb::RedbDatabase,
    event_message::signed_event_message::{Message, Notice},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
        Processor,
    },
};
use serde::Deserialize;
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

    let (mut accepted, mut refused, mut skipped) = (0, 0, 0);

    for case in &cases {
        if !case.skipped.is_empty() {
            println!("  SKIPPED  {:30} {}", case.label, case.skipped);
            skipped += 1;
            continue;
        }
        // Only key events are judged here. keriox's transaction-event support
        // lives behind a different surface, and claiming to have tested it by
        // running it through the key-event processor would be worse than saying
        // it is untested.
        if case.kind != "kel" && case.kind != "delegation" {
            println!(
                "  SKIPPED  {:30} kind {:?} is not a key event",
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
