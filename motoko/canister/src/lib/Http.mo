/// The management canister's HTTPS-outcall surface.
///
/// A module rather than declarations at the top of the mixin that uses them: a
/// bare `let` in a `mixin` block is implicitly stable, and neither an actor
/// reference nor a plain constant belongs in persisted state.

module {
  /// Where `call_api_with_secret` sends its authenticated request.
  ///
  /// postman-echo's `/basic-auth` genuinely **evaluates** the credential — the
  /// documented `postman:password` gets `200 {"authenticated":true}`, anything
  /// else gets `401` — and it does not echo the credential back, which matters
  /// because the response body enters replicated state.
  public let DEMO_API_ENDPOINT = "https://postman-echo.com/basic-auth";

  public let IC : actor {
    http_request : shared HttpRequestArgs -> async HttpRequestResult;
  } = actor ("aaaaa-aa");

  public type HttpHeader = { name : Text; value : Text };

  public type HttpRequestResult = {
    status : Nat;
    headers : [HttpHeader];
    body : Blob;
  };

  public type TransformArgs = { response : HttpRequestResult; context : Blob };

  public type HttpRequestArgs = {
    url : Text;
    max_response_bytes : ?Nat64;
    headers : [HttpHeader];
    body : ?Blob;
    method : { #get; #post; #head };
    transform : ?{
      function : shared query TransformArgs -> async HttpRequestResult;
      context : Blob;
    };
  };
}
