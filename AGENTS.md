# Working on OpenProxy

@/home/mark/.codex/RTK.md

Prefix shell commands with `rtk`. Use `rtk proxy <command>` for output without filters.

## Project and scope

OpenProxy is a Linux HTTP/HTTPS debugging proxy. One Rust binary contains the proxy and the React/TypeScript inspector.
Node is necessary for builds and development. The compiled application runs without a Node service or external UI assets.

- Keep changes small. Use current modules, UI components, and dependencies.
- Keep user documentation in [README.md](README.md). Update it when behavior, setup, flags, or limits change. Make sure that examples agree with the code and `openproxy --help`.
- Keep regression tests for behavior. Add plans, status documents, demo generators, screenshot scripts, or release tools only when necessary for the task.
- Preserve unrelated work. Do not commit captures, credentials, certificates, private keys, browser data, logs, or generated build/test files. Use only fictional traffic without sensitive data in README screenshots.

## Documentation and comments

Use [ASD-STE100 Simplified Technical English](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf) for documentation and comments.

- Use active voice. Write instructions as commands, with one instruction per sentence.
- Use no more than 20 words in an instruction or 25 words in a description sentence.
- Keep each paragraph on one topic, with no more than six sentences.
- Use approved words and standard technical terms. Use one term for each item.
- Keep UI labels, identifiers, commands, and protocol names.
- Remove words that are not necessary. Do not use idioms or semicolons.
- Use comments to explain constraints or reasons. Do not repeat the code.
- Keep license text and generated files.

## Repository map

| Location                                                                      | Responsibility                                                                                   |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `src/main.rs`, `src/config.rs`                                                | CLI, startup, listeners, shutdown, saved data, settings validation.                              |
| `src/proxy.rs`, `src/connector.rs`, `src/network.rs`                          | HTTP/HTTPS streams, upstream TLS verification, SOCKS, reverse proxy, TCP forwarding.             |
| `src/api.rs`, `src/store.rs`, `src/compare.rs`                                | Inspector API protection, capture limits, native/HAR sessions, comparison.                       |
| `src/rules.rs`, `src/breakpoints.rs`, `src/simulation.rs`, `src/mirror.rs`    | Ordered edits, URL mapping, breakpoints, network simulation, body mirrors.                       |
| `src/ca.rs`, `src/auth.rs`, `src/linux.rs`, `src/process.rs`                  | CA identity, private credentials, desktop proxy setup, client process identification.            |
| `src/protocols.rs`, `src/protocols/`, `src/websocket.rs`, `src/validation.rs` | Protocol/frame inspection limits, consent for external validation.                               |
| `web/src/`, `web/src/components/ui/`, `web/style.css`                         | Inspector, local shadcn/ui controls, Tailwind theme. Use shared controls and format/API helpers. |
| `web/public/openproxy.svg`, `docs/images/`                                    | App logo and README images. Use the same logo in the app and README.                             |
| `tests/`, `.github/workflows/ci.yml`                                          | Local protocol, browser, and platform tests. Debug/release verification.                         |

## Build and development

Use Rust **1.89+** and Node **22.12+**. CI uses stable Rust and Node **24**.
Build web assets before Rust. `build.rs` uses `web/dist/index.html`. The Rust build embeds `web/dist` in the binary.

```sh
rtk npm --prefix web ci
rtk npm --prefix web run build
rtk cargo build --locked
```

For local work, use an isolated ignored data directory:

```sh
rtk proxy ./target/debug/openproxy --data-dir test-artifacts/agent-proxy
```

The default proxy address is `127.0.0.1:8080`. The default inspector address is `127.0.0.1:8081`.
Use the printed inspector URL with `/#TOKEN`. Each process has its own token.
Do not use or change the user's `data/` directory for tests.

For UI development, run `rtk npm --prefix web run dev`. Open its URL with the same token fragment.
Vite forwards `/api` to the Rust inspector on **8081**.
For embedded UI verification, rebuild the web assets and the Rust binary. A Vite preview does not update the binary.

## Code edit checks

- After web edits, run `rtk npm --prefix web run format`. Make sure that `rtk npm --prefix web run format:check` and `rtk npm --prefix web run build` pass. Prettier uses `prettier-plugin-tailwindcss` to sort classes, including `cn()` and `cva()` calls.
- After Rust edits, run `rtk cargo fmt`. Make sure that `rtk cargo fmt --check` and `rtk cargo clippy --locked --all-targets -- -D warnings` pass. Run `rtk cargo test --locked`. Run the relevant protocol tests. Correct warnings. Do not suppress checks.
- After documentation edits, run `rtk proxy web/node_modules/.bin/prettier --check README.md AGENTS.md`. Make sure that local links, flags, and file references are correct. For formatting corrections, use the same executable with `--write`.
- Before handover, run `rtk git diff --check`. Report passed and skipped checks. Local results do not prove remote CI results, device acceptance, or deployment success.

## Selecting tests

Protocol and browser tests use a compiled binary, with `target/debug/openproxy` as the default.
After source or embedded-web edits, rebuild the binary.
For a release build, set `OPENPROXY_BIN=target/release/openproxy`. Use a task-specific variable for other overrides.

| Changed behavior                                                              | Required checks                                                                                                     |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Core forwarding, rules, replay, captures, sessions, HAR, breakpoints          | `rtk proxy python3 tests/integration.py`                                                                            |
| SOCKS/PAC, reverse proxy, TCP forwarding                                      | `rtk proxy python3 tests/transport.py`                                                                              |
| TLS, CA identity, upstream proxies, authentication, mTLS, connection metadata | `rtk proxy python3 tests/connections.py`                                                                            |
| WebSocket, Protobuf, gRPC, AMF, external validation                           | `rtk proxy python3 tests/protocols.py`                                                                              |
| Latency, bandwidth, offline mode, failures, byte limits                       | `rtk proxy python3 tests/simulation.py`. Add `--long` for the upload longer than 120 seconds. CI uses `--long`.     |
| GNOME setup or client process identification                                  | `rtk proxy python3 tests/linux.py`                                                                                  |
| Frontend helpers, inspector controls, accessibility                           | `rtk proxy node --experimental-strip-types --test tests/frontend.test.mjs` and `rtk proxy python3 tests/browser.py` |
| Protocol inspector UI or shared browser helper                                | `rtk proxy python3 tests/protocols-browser.py` and `rtk proxy python3 tests/browser.py`                             |

Protocol tests use Python 3, OpenSSL, curl with HTTP/2, and Node for HTTP/2/WebSocket origins.
Tests use local origins and private temporary data. Keep screenshots and other test files in ignored `test-artifacts/`.
Tests do not use public websites.

Linux tests use an isolated GSettings backend. Install `gsettings` and GNOME proxy schemas for these tests. Do not skip this coverage.

Browser tests use **agent-browser 0.38.2** and its Chromium installation, as in CI.
If necessary, install with `rtk npm install --global agent-browser@0.38.2`. Then run `rtk proxy agent-browser install --with-deps`.
Tests use named browser sessions and close them.
If details load asynchronously, wait for selectors or state. Keep the delayed-detail regression in `tests/browser.py`.

Optional `rtk proxy python3 tests/android.py` uses an Android SDK, default API 36 x86_64 image, JDK, and OpenSSL.
It uses a disposable emulator. Do not use a physical device or the user's emulator.
Automated tests do not replace iPhone acceptance tests.

CI runs Rust/frontend checks and all protocol/browser tests.
It then builds the release binary and runs integration, transport, connection, and protocol tests.
CI does not create or upload release archives.

## Contracts

- **Trust boundaries:** keep the inspector on loopback. Keep process-token authentication and Host/Origin checks. Limit proxy access to explicit client allow lists. Keep validation of settings, headers, URLs, imported sessions, and protocol inputs.
- **TLS and CA identity:** validate upstream certificates and hostnames. Keep the saved CA identity and private file permissions. If the identity is damaged or unreadable, fail. Do not replace trusted keys automatically. Send client certificates only to explicitly allowed hosts.
- **Streaming:** capture limits must not truncate forwarded data. Keep binary bodies, repeated headers, HTTP framing, trailers, cancellation, and half-close behavior. Buffer streams only in current edit/inspection paths with size limits.
- **Edits and replay:** keep original/effective snapshots consistent with their URL, method, body, and status. Do not apply edits twice on replay. Keep native/HAR compatibility, rule order, and framing validation.
- **Resource limits:** keep retention, edit, queue, deadline, connection, and protocol decoder limits. For changes to these limits, do tests for malformed inputs, large inputs, and cancellation.
- **Privacy:** captures and exports can contain secrets. Files are not encrypted at rest. Keep generated data private. Get new explicit consent for external validation of each selected body. Do not send captured URLs, headers, or cookies with it.
- **Desktop/device changes:** startup must not change desktop proxy settings or install trust certificates. Use isolated settings/data and disposable devices for tests. Do not change real desktop or device state during verification.

<!-- CODEGRAPH_START -->

## CodeGraph

If `.codegraph/` exists at the repository root, use CodeGraph before text searches or file reads to understand code.

- Use the `codegraph_explore` MCP tool when available. Query a file or symbol for current source and call paths. If the tool is deferred, load it by name.
- Otherwise, run `rtk proxy codegraph explore "<symbol names or question>"`.

If `.codegraph/` is absent, use `rtk proxy rg` or `rtk proxy rg --files`. Do not create an index without the user's request.

<!-- CODEGRAPH_END -->

## Fly.io — read only

Get explicit approval for each specified `fly`/`flyctl` action that changes infrastructure. Prior approvals do not apply.
This includes deploy, scale, machine start/stop/destroy/update, secrets, apps, regions, and configuration changes.

Read-only status, logs, machine lists, organization lists, and Prometheus queries are allowed.
Before a write, prepare a concrete proposal. Ask for approval before execution.
