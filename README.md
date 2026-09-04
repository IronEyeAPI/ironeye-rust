# IronEye for Rust

The official Rust client for the [IronEye](https://ironeye.org) API: document
analysis over bytes you send, and normalised collection from public sources,
behind one key.

```toml
ironeye = "1"
```

## Features

- Every analysis route, the async job path with `await_job`, the collection
  catalogue and the data-subject-rights endpoints.
- Deserialised response types, with each module's own body left as `Value`.
- `Error::Api` carries the code, retry verdict, request id and suggested action.
- Retries on the server's own `retryable` flag, honouring `Retry-After`.
- `tracing` spans per request. No credential, no payload.
- `#![forbid(unsafe_code)]`.

Full documentation, including every endpoint and every option, is at
**https://ironeye.org/docs/sdk/rust**.

---

Direct Softworks · [MIT](LICENSE) · issues and pull requests welcome
