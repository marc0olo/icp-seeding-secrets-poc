//! Golden vectors and validation tests for the wire format.
//!
//! These vectors are the contract. They exist so that a future TypeScript,
//! Motoko or third-party implementation can be checked byte-for-byte against
//! this one, rather than "looking right". Changing any of them is a protocol
//! break that orphans every previously sealed ciphertext.

use candid::Principal;
use sealed_secrets_core::*;

const SUITE_HEX: &str = "6963702d7365616c65642d736563726574732d7631";

#[test]
fn suite_label_is_pinned() {
    assert_eq!(hex::encode(SUITE), SUITE_HEX);
    assert_eq!(SUITE.len(), 21);
}

#[test]
fn context_and_key_label_golden_vectors() {
    assert_eq!(
        hex::encode(CONTEXT),
        "6963702d7365616c65642d736563726574732d7631"
    );
    assert_eq!(
        hex::encode(KEY_LABEL),
        "6963702d7365616c65642d736563726574732d76312e6b657973"
    );
}

/// The two select different things — the context selects the keypair, the label
/// selects a key within it — so they must never be the same bytes.
#[test]
fn context_and_key_label_differ() {
    assert_ne!(CONTEXT, KEY_LABEL);
}

#[test]
fn secret_name_validation() {
    let max_name = "n".repeat(MAX_NAME_LEN);
    for good in [
        "A",
        "DUMMY_API_KEY",
        "billing.live-key_2",
        "0",
        max_name.as_str(),
    ] {
        assert!(validate_secret_name(good).is_ok(), "rejected {good:?}");
    }

    assert_eq!(validate_secret_name(""), Err(FormatError::EmptyName));
    assert_eq!(
        validate_secret_name(&"n".repeat(MAX_NAME_LEN + 1)),
        Err(FormatError::NameTooLong {
            len: MAX_NAME_LEN + 1
        })
    );

    // Rejected on purpose: a slash invites path-like names, a space invites
    // copy-paste errors, and non-ASCII invites two visually identical names
    // becoming two different entries.
    for (bad, ch) in [("a/b", '/'), ("a b", ' '), ("k\u{e9}y", '\u{e9}')] {
        assert_eq!(
            validate_secret_name(bad),
            Err(FormatError::InvalidNameChar { ch }),
            "accepted {bad:?}"
        );
    }
}

fn test_canister() -> Principal {
    Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai").unwrap()
}

#[test]
fn public_key_derivation_is_deterministic() {
    let ctx = CONTEXT.to_vec();
    let a = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap();
    let b = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap();
    assert_eq!(a.serialize(), b.serialize());
    assert_eq!(a.serialize().len(), 96);
}

/// The trap this guards against: mainnet and PocketIC both have a key named
/// `key_1`, backed by *different* master keys — by design, since a local
/// environment cannot hold mainnet's master secret. The consequence is that a
/// key name does not identify a key, so selecting the table by name is a guess,
/// and a wrong guess silently produces a ciphertext nobody can decrypt.
/// `ic-vetkeys`' `management_canister::compute_vrf` selects by name today.
#[test]
fn same_key_name_differs_across_master_key_sources() {
    let ctx = CONTEXT.to_vec();
    let mainnet = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap();
    let pocketic = derive_public_key(
        MasterKeySource::PocketIc,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap();
    assert_ne!(mainnet.serialize(), pocketic.serialize());
}

#[test]
fn unknown_key_name_is_reported() {
    let ctx = CONTEXT.to_vec();
    let err = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("no_such_key"),
        &test_canister(),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(
        err,
        FormatError::UnknownKeyId {
            source: MasterKeySource::Mainnet,
            key_name: "no_such_key".to_string()
        }
    );
}

/// Each of these is a way a client could end up deriving a key the canister
/// cannot decrypt with. None can be caught by inspection — they all produce a
/// perfectly well-formed key — so what matters is that each yields a *different*
/// key, which is why `set` decrypts before storing rather than trusting the
/// blob it was handed.
#[test]
fn every_mismatch_yields_a_different_key() {
    let other_canister = Principal::from_text("bd3sg-teaaa-aaaaa-qaaba-cai").unwrap();

    let correct = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        CONTEXT,
    )
    .unwrap()
    .serialize();

    let cases: Vec<(&str, MasterKeySource, &str, Principal, &[u8])> = vec![
        (
            "wrong context",
            MasterKeySource::Mainnet,
            "key_1",
            test_canister(),
            KEY_LABEL,
        ),
        (
            "wrong canister",
            MasterKeySource::Mainnet,
            "key_1",
            other_canister,
            CONTEXT,
        ),
        (
            "wrong master key table",
            MasterKeySource::PocketIc,
            "key_1",
            test_canister(),
            CONTEXT,
        ),
        (
            "wrong key name",
            MasterKeySource::Mainnet,
            "test_key_1",
            test_canister(),
            CONTEXT,
        ),
    ];

    for (label, source, key_name, canister, context) in cases {
        let derived = derive_public_key(source, &key_id(key_name), &canister, context)
            .unwrap()
            .serialize();
        assert_ne!(derived, correct, "{label} produced the same key");
    }
}

#[test]
fn plaintext_length_is_recoverable_from_ciphertext_length() {
    assert_eq!(IBE_OVERHEAD, 136);
    assert_eq!(plaintext_len(136 + 51), Some(51));
    assert_eq!(plaintext_len(10), None);
}
