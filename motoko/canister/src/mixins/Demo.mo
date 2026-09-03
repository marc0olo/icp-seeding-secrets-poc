/// The demo use case: spending a sealed secret on an outbound call.
///
/// Deliberately separate from `Secrets.mo`. Those six endpoints are the part
/// meant to be a standard — the part a client can rely on across
/// implementations. This is one application's answer to "now what do I do with
/// the secret", and a real canister writes its own. The mixin boundary is what
/// makes that distinction structural instead of a comment.
///
/// Mirrors `call_api_with_secret` and `strip_response` in
/// `rust/canister/src/lib.rs`.

import Guard "../lib/Guard";
import Http "../lib/Http";
import Store "../Store";
import Types "../Types";

import Error "mo:core/Error";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Text "mo:core/Text";

mixin (secrets : Store.Secrets) {

  /// The actual use case: authenticate an outbound HTTPS request with a sealed
  /// secret, without the secret ever leaving the canister.
  ///
  /// Returns only the HTTP status. Returning the body would let a hostile
  /// endpoint echo the `Authorization` header straight back out through this
  /// canister's public interface.
  ///
  /// `idempotencyKey` is **not optional in practice.** An HTTPS outcall fans out
  /// to every node in the subnet, each of which issues its own request; without
  /// a key, an endpoint that mutates state sees N charges, N sends, N writes.
  /// This demo endpoint is a read, so nothing here would break without it —
  /// which is exactly why it is present anyway, as the thing to copy.
  ///
  /// Note where the plaintext goes. The request — url, headers and body — enters
  /// **replicated state on every node** before any of them executes the call. On
  /// a SEV-SNP subnet that memory and the checkpoints behind it are encrypted;
  /// on any other subnet the secret is readable by every node operator the
  /// moment this runs.
  public shared ({ caller }) func call_api_with_secret(
    name : Text,
    idempotencyKey : Text,
  ) : async Types.Result<Nat16> {
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let record = switch (secrets.get(name)) {
      case (?r) r;
      case null { return #Err(#NotFound) };
    };

    let token = switch (record.plaintext.decodeUtf8()) {
      case (?t) t;
      case null { return #Err(#Internal("secret is not valid UTF-8")) };
    };

    let response = try {
      await (with cycles = 50_000_000_000) Http.IC.http_request({
        url = Http.DEMO_API_ENDPOINT;
        // Keep this tight: the call is priced on it.
        max_response_bytes = ?(2_048 : Nat64);
        headers = [
          // The secret is the whole header value.
          { name = "Authorization"; value = token },
          { name = "Idempotency-Key"; value = idempotencyKey },
          { name = "User-Agent"; value = "icp-sealed-secrets-poc" },
        ];
        body = null;
        method = #get;
        transform = ?{ function = strip_response; context = "" : Blob };
      });
    } catch (e) {
      return #Err(#Internal("http_request failed: " # e.message()));
    };

    if (response.status > 65535) {
      return #Err(#Internal("implausible status code"));
    };
    #Ok(response.status.toNat16());
  };

  /// Makes an HTTP response deterministic across the nodes that fetched it.
  ///
  /// Drops every response header — they carry `Date`, request ids and cookies
  /// that differ per node, which would break consensus — and, incidentally,
  /// stops an endpoint that echoes our `Authorization` header from smuggling the
  /// secret into replicated state.
  ///
  /// **This passes the body through unchanged, which is only safe because the
  /// demo endpoint returns a constant.** If yours returns a timestamp, a request
  /// id or anything else that differs between fetches, normalise it here too.
  /// Local testing will not catch this: a local replica issues exactly one
  /// request, so a varying body agrees with itself, while on mainnet every node
  /// fetches independently and the call fails.
  public shared query func strip_response(args : Http.TransformArgs) : async Http.HttpRequestResult {
    {
      status = args.response.status;
      headers = [] : [Http.HttpHeader];
      body = args.response.body;
    };
  };
};
