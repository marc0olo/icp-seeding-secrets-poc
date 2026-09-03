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
fn context_golden_vectors() {
    assert_eq!(
        hex::encode(sealed_secrets_context("").unwrap()),
        "01156963702d7365616c65642d736563726574732d763100"
    );
    assert_eq!(
        hex::encode(sealed_secrets_context("demo").unwrap()),
        "01156963702d7365616c65642d736563726574732d76310464656d6f"
    );
}

#[test]
fn identity_golden_vectors() {
    assert_eq!(
        hex::encode(sealed_secrets_identity(0)),
        "01156963702d7365616c65642d736563726574732d763100000000"
    );
    assert_eq!(
        hex::encode(sealed_secrets_identity(1)),
        "01156963702d7365616c65642d736563726574732d763100000001"
    );
    assert_eq!(
        hex::encode(sealed_secrets_identity(u32::MAX)),
        "01156963702d7365616c65642d736563726574732d7631ffffffff"
    );
}

/// Length prefixes exist so that no two distinct inputs collide. Without them,
/// a suite of `"ab"` with separator `"c"` and a suite of `"abc"` with an empty
/// separator would encode identically.
#[test]
fn context_encoding_is_unambiguous() {
    let a = sealed_secrets_context("x").unwrap();
    let b = sealed_secrets_context("").unwrap();
    assert_ne!(a, b);
    assert_eq!(a.len(), b.len() + 1);
}

#[test]
fn app_separator_length_is_bounded() {
    let ok = "a".repeat(MAX_APP_SEPARATOR_LEN);
    assert!(sealed_secrets_context(&ok).is_ok());

    let too_long = "a".repeat(MAX_APP_SEPARATOR_LEN + 1);
    assert_eq!(
        sealed_secrets_context(&too_long),
        Err(FormatError::AppSeparatorTooLong {
            len: MAX_APP_SEPARATOR_LEN + 1
        })
    );
}

#[test]
fn secret_name_validation() {
    let max_name = "n".repeat(MAX_NAME_LEN);
    for good in [
        "A",
        "OPENAI_API_KEY",
        "stripe.live-key_2",
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
    let ctx = sealed_secrets_context("").unwrap();
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
/// `key_1`, backed by *different* master keys. Selecting the table by key name
/// would silently produce a ciphertext nobody can decrypt. `ic-vetkeys`'
/// `management_canister::compute_vrf` has exactly this bug today.
#[test]
fn same_key_name_differs_across_master_key_sources() {
    let ctx = sealed_secrets_context("").unwrap();
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
    let ctx = sealed_secrets_context("").unwrap();
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

#[test]
fn verification_accepts_a_matching_key() {
    let ctx = sealed_secrets_context("").unwrap();
    let derived = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap();

    assert!(verify_reported_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
        &derived.serialize(),
    )
    .is_ok());
}

/// Each of these is a way a client could end up encrypting to a key the canister
/// cannot decrypt with. All must be caught before any ciphertext is produced.
#[test]
fn verification_rejects_every_mismatch() {
    let ctx = sealed_secrets_context("").unwrap();
    let other_ctx = sealed_secrets_context("different").unwrap();
    let other_canister = Principal::from_text("bd3sg-teaaa-aaaaa-qaaba-cai").unwrap();

    let reported = derive_public_key(
        MasterKeySource::Mainnet,
        &key_id("key_1"),
        &test_canister(),
        &ctx,
    )
    .unwrap()
    .serialize();

    /// One way a client could derive a key the canister cannot decrypt with.
    struct Case {
        label: &'static str,
        source: MasterKeySource,
        key_name: &'static str,
        canister: Principal,
        context: Vec<u8>,
        reported: Vec<u8>,
    }

    let cases = vec![
        Case {
            label: "wrong context",
            source: MasterKeySource::Mainnet,
            key_name: "key_1",
            canister: test_canister(),
            context: other_ctx,
            reported: reported.clone(),
        },
        Case {
            label: "wrong canister",
            source: MasterKeySource::Mainnet,
            key_name: "key_1",
            canister: other_canister,
            context: ctx.clone(),
            reported: reported.clone(),
        },
        Case {
            label: "wrong master key table",
            source: MasterKeySource::PocketIc,
            key_name: "key_1",
            canister: test_canister(),
            context: ctx.clone(),
            reported: reported.clone(),
        },
        Case {
            label: "wrong key name",
            source: MasterKeySource::Mainnet,
            key_name: "test_key_1",
            canister: test_canister(),
            context: ctx.clone(),
            reported: reported.clone(),
        },
        Case {
            label: "truncated key",
            source: MasterKeySource::Mainnet,
            key_name: "key_1",
            canister: test_canister(),
            context: ctx.clone(),
            reported: reported[..95].to_vec(),
        },
    ];

    for case in cases {
        assert_eq!(
            verify_reported_public_key(
                case.source,
                &key_id(case.key_name),
                &case.canister,
                &case.context,
                &case.reported,
            ),
            Err(FormatError::PublicKeyMismatch),
            "{} was not rejected",
            case.label
        );
    }
}

#[test]
fn plaintext_length_is_recoverable_from_ciphertext_length() {
    assert_eq!(IBE_OVERHEAD, 136);
    assert_eq!(plaintext_len(136 + 51), Some(51));
    assert_eq!(plaintext_len(10), None);
}
