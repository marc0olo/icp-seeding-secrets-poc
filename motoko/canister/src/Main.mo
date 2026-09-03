/// A Motoko canister that receives secrets sealed with vetKD IBE.
///
/// The composition root, and nothing else: state declarations and the mixins
/// that operate on them. Every endpoint lives in `mixins/`, every rule in
/// `lib/`, every type in `Types.mo` and `Store.mo`.
///
/// Mirrors `rust/canister/src/lib.rs`. Where the two diverge internally, the
/// reason is written down at the divergence — see `lib/Keys.mo` on what is
/// cached and why.
///
/// ⚠️ This depends on an **experimental, unaudited** BLS12-381 implementation.
/// It is a demonstration that Motoko can do this, not a recommendation that it
/// should yet.

import Keys "lib/Keys";
import Store "Store";
import SecretsApi "mixins/Secrets";
import DemoApi "mixins/Demo";

import Principal "mo:core/Principal";

persistent actor class SealedSecrets(initArgs : { key_name : Text }) = self {

  /// Pinned at first init and kept across upgrades. See `Store.Config`.
  let config : Store.Config = Store.defaultConfig(initArgs.key_name);

  /// The secrets themselves, decrypted once at `set`. See `Store.SealedRecord`
  /// for why this holds plaintext rather than ciphertext.
  let secrets : Store.Secrets = Store.emptySecrets();

  /// Derived keys. Deliberately **not** `transient`: under orthogonal
  /// persistence they survive an upgrade for free, so the canister does not pay
  /// a `vetkd_derive_key` — the call, its fee and a consensus round — to
  /// reproduce something the runtime was going to keep anyway. `lib/Keys.mo`
  /// explains why that is a cost decision and not a security one.
  let caches : Keys.Caches = Keys.emptyCaches();

  /// What `lib/Keys` needs, gathered once. A record, so the cache writes inside
  /// it are seen here rather than made against a copy.
  transient let keyCtx : Keys.Context = { keyName = config.keyName; caches };

  /// The sealed-secrets interface — the part meant to be a standard.
  include SecretsApi(config, secrets, keyCtx, Principal.fromActor(self));

  /// One application's answer to "now what do I do with the secret". Separate
  /// on purpose: a real canister replaces this and keeps the mixin above.
  include DemoApi(secrets);
};
