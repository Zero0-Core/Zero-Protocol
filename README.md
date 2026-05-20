# Zero Protocol

> **A decentralised, end-to-end encrypted messaging protocol — written entirely in memory-safe Rust.**

Zero Protocol is a privacy-first, anonymous, and highly resilient communications platform. It operates without any central servers, relies on a self-healing Kademlia DHT peer network, and encrypts every message with layered cryptographic primitives including the Signal Double Ratchet, X25519 Diffie-Hellman key exchange, and a Tor-inspired 3-hop Onion Routing system.

> [!TIP]
> **New to Zero?** Read our [Decentralisation Philosophy](DECENTRALIZATION.md) to understand why Zero is 100% serverless and how every user powers the network.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)  
2. [Crate Reference](#crate-reference)  
3. [Security Model](#security-model)  
4. [Building & Running](#building--running)  
5. [Compilation Profiles](#compilation-profiles)  
6. [Code Quality & Linting](#code-quality--linting)  
7. [Workspace Dependencies](#workspace-dependencies)  
8. [Project Status](#project-status)

---

## Architecture Overview

The workspace is organized into two top-level categories: **8 core protocol crates** and **4 developer tools**.

```text
zero-protocol/
├── Cargo.toml                  # Workspace manifest — global lints & hardened build profiles
│
├── crates/                     # Core Protocol Engine
│   ├── zero-crypto/            # Cryptographic primitives (Noise IK, AEAD, KDF, BIP39)
│   ├── zero-dht/               # Kademlia DHT — routing table, packet codec, bucket logic
│   ├── zero-session/           # Double Ratchet sessions, file transfer, group chat
│   ├── zero-net/               # Network layer — UDP, QUIC, UPnP, LAN multicast discovery
│   ├── zero-onion/             # 3-hop Onion Routing — path selection, wrapping, peeling
│   ├── zero-offload/           # Store-and-forward offline blob storage (PoW-gated)
│   ├── zero-core/              # Orchestration — ZeroNode event loop, packet multiplexer
│   └── zero-api/               # UniFFI API boundary for Android / iOS native frontends
│
└── tools/                      # Developer Executables
    ├── zero-cli/               # Interactive CLI terminal for local testing
    ├── zero-bootstrap/         # Standalone DHT bootstrap node
    ├── zero-push/              # APNs / FCM mobile push alert broker
    └── zero-bridge/            # Matrix / XMPP federation bridge
```

### Layered Stack

```
  [ zero-api ]        ← UniFFI boundary (Android / iOS)
       │
  [ zero-core ]       ← ZeroNode: event loop, packet routing, subsystem orchestration
       │
  ┌────┴────┬──────────┬───────────┬────────────┐
  │         │          │           │            │
zero-dht  zero-onion  zero-session  zero-net  zero-offload
  │         │          │           │            │
  └────┬────┴──────────┴───────────┘            │
       │                                        │
  [ zero-crypto ]     ← Shared cryptographic primitives
```

---

## Crate Reference

### `zero-crypto` — Cryptographic Primitives

The foundational cryptography library. All other crates depend on this crate and **nowhere else** for crypto.

| Module | Purpose |
|---|---|
| `keypair` | Static X25519 / Ed25519 keypair structs with `zeroize`-on-drop |
| `aead` | ChaCha20-Poly1305 authenticated encryption & decryption |
| `kdf` | HKDF-SHA-256 key derivation function |
| `noise` | Noise IK handshake using the `snow` framework |
| `argon2` | Argon2id password-based key derivation |
| `bip39` | BIP-39 mnemonic seed phrase generation and restoration |
| `signature` | Ed25519 blob signing for offline storage attestation |

**Key design decisions:**
- `unsafe_code = "forbid"` enforced at the workspace level.
- `zeroize` is applied to all keypair material so secrets are cleared from memory immediately after use.
- All fallible operations return `Result<_, ZeroError>` — no panics.

---

### `zero-dht` — Kademlia DHT

Implements a hardened XOR-metric Kademlia DHT for decentralized peer discovery and routing.

| Module | Purpose |
|---|---|
| `node` | `DhtPublicKey`, `NodeInfo` (identity, address, reputation, failures) |
| `routing` | `RoutingTable` — K-bucket management with bucket-splitting and LRU eviction |
| `packet` | `DhtPacket` / `DhtPayload` — binary-encoded FindNode / FindNodeResponse |
| `lookup` | Iterative α-parallel Kademlia node lookup algorithm |

**Key design decisions:**
- Routing table tracks `consecutive_failures` per peer for automatic eviction of stale nodes.
- `find_closest` is O(log n) over K-buckets and returns at most K (= 20) candidates.
- All distance metrics use constant-time XOR (no early-exit leaks).

---

### `zero-session` — Encrypted Sessions

Manages long-lived encrypted conversations, file transfers, and group channels.

| Module | Purpose |
|---|---|
| `ratchet` | Signal Double Ratchet (X3DH + symmetric ratchet for forward secrecy) |
| `file` | Chunked file transfer state machine (request → chunk → assemble) |
| `group` | Hierarchical group chat with `Owner` → `Admin` → `Member` roles |
| `manager` | `SessionManager` — concurrent session registry keyed by public key |

**Key design decisions:**
- Double Ratchet provides **forward secrecy** (past messages safe if current key leaks) and **break-in recovery** (future messages heal after compromise).
- Group permissions are strictly validated at every role-change operation — no privilege escalation possible.
- File transfers are streamed in chunks with an explicit `Complete` / `Abort` terminal state to prevent resource exhaustion.

---

### `zero-net` — Network Transport

Abstracts all I/O primitives behind a unified interface.

| Module | Purpose |
|---|---|
| `udp` | `UdpManager` — async UDP socket with `recv_from` / `send_to` |
| `transport` | `TransportSelector` — dispatches packets over UDP (QUIC planned) |
| `upnp` | UPnP IGD port mapping via the `igd` crate |
| `lan` | IPv4 multicast LAN broadcast for local peer discovery |
| `quic` | QUIC transport initialization (rcgen + rustls + quinn) |

---

### `zero-onion` — Onion Routing

A Tor-inspired 3-hop onion routing layer that hides both sender identity and message contents.

| Module | Purpose |
|---|---|
| `packet` | `OnionPacket`, `OnionCommand` (Forward / Deliver) — the wire format |
| `path` | `OnionPath` — selects 3 random relay nodes from the routing table |
| `forward` | `peel_and_forward` — strips one AEAD layer and returns the next routing command |
| `announce` | Announce key construction for offline rendezvous |

**How it works:**
1. The sender wraps the payload in 3 nested AEAD layers (innermost = destination).
2. Each hop decrypts exactly one layer, revealing only the *next hop* address.
3. No single relay ever knows both the origin and the destination.
4. Each layer uses an ephemeral X25519 ECDH key so sessions are unlinkable.

---

### `zero-offload` — Offline Blob Storage

Allows messages to be stored at DHT nodes so offline recipients can retrieve them later.

| Module | Purpose |
|---|---|
| `blob` | `OfflineBlob` — AEAD-encrypted payload with a Blake2s PoW ticket |
| `store` | `BlobStore` — in-memory store with per-key retrieval and TTL-based cleanup |
| `pow` | Blake2s Proof-of-Work: anti-spam gate for store requests |

**Key design decisions:**
- Storing a blob requires a valid PoW token (`target_difficulty` leading zero bits over nonce + announce_key).
- `cleanup_expired` runs as a background garbage-collection task on a 1-hour timer inside `ZeroNode`.

---

### `zero-core` — Orchestration Layer

The central node that ties all subsystems together and drives the async event loop.

| Module | Purpose |
|---|---|
| `node` | `ZeroNode` — owns transport, routing table, keypair, blob store |
| `packet` | Wire-level packet codec: magic bytes, `PacketType`, encode/decode |
| `error` | `CoreError` — unified error type (wraps all subsystem errors) |

**`ZeroNode` background tasks (started by `run_background_tasks`):**
1. **UPnP mapping** — attempts to open the listening port on the gateway router.
2. **LAN discovery loop** — broadcasts presence on the local network via multicast.
3. **Packet ingestion loop** — the main `recv_from` loop, dispatching to handlers:
   - `Ping` — liveness check.
   - `FindNode` / `FindNodeResponse` — Kademlia DHT routing.
   - `OnionRequest` — peel one encryption layer and either forward or deliver.
   - `SessionMessage` — encrypted Double Ratchet payload.
   - `OffloadStore` / `OffloadRetrieve` — offline message blob management.
4. **GC loop** — prunes expired offline blobs every hour.

---

### `zero-api` — UniFFI Public API

Exposes a stable, language-agnostic interface for mobile (Android / iOS) and desktop frontends.

Generated via Mozilla UniFFI, the bindings allow Swift (iOS) and Kotlin (Android) to call into the Rust core without any unsafe FFI boilerplate.

---

## Security Model

| Threat | Mitigation |
|---|---|
| **Passive eavesdropping** | All messages are end-to-end encrypted with ChaCha20-Poly1305 (AEAD). |
| **Man-in-the-middle** | Noise IK handshake authenticates both parties with their long-term static keys. |
| **Forward secrecy violation** | Signal Double Ratchet rotates keys per-message; compromising one key never reveals past messages. |
| **Traffic analysis / de-anonymization** | 3-hop Onion Routing with per-session ephemeral keys makes origin/destination unlinkable. |
| **Offline message spam** | Blake2s Proof-of-Work is required to store any blob at a relay node. |
| **Memory disclosure** | All cryptographic key material implements `zeroize`; memory is wiped immediately after use. |
| **Binary reverse engineering** | Release builds strip all debug symbols (`strip = "symbols"`) and abort on panic (no unwinding frames). |
| **Unsafe Rust** | `unsafe_code = "forbid"` is enforced globally across the entire workspace. |
| **Privilege escalation in groups** | Group role changes are validated against a strict `Owner > Admin > Member` hierarchy. |
| **Stale / malicious peer DoS** | `RoutingTable` tracks `consecutive_failures` and evicts unresponsive peers automatically. |

---

## Building & Running

### Prerequisites

- **Rust** (stable, 1.74+) — install via [rustup](https://rustup.rs/)
- **Cargo** (included with Rust)

```bash
rustup update stable
```

---

### 1. Build — Development Mode

Fast incremental compilation with full debug symbols:

```bash
cargo build
```

### 2. Build — Release Mode

Fat LTO, stripped symbols, `panic = "abort"`, maximum optimization:

```bash
cargo build --release
```

### 3. Run the CLI Terminal

Interactive command-line chat client for local development and integration testing:

```bash
cargo run -p zero-cli
```

### 4. Run the Bootstrap Node

Launch a standalone DHT bootstrap routing hub that new peers can use to join the network:

```bash
cargo run -p zero-bootstrap
```

### 5. Run All Tests

Execute the full test suite across every crate and module:

```bash
cargo test
```

### 6. Run Tests for a Specific Crate

```bash
cargo test -p zero-dht
cargo test -p zero-session
cargo test -p zero-onion
```

### 7. Lint the Workspace

```bash
cargo clippy --workspace --all-targets
```

---

## Compilation Profiles

Configured in the root `Cargo.toml`:

| Profile | `opt-level` | `debug` | `incremental` | `lto` | `codegen-units` | `panic` | `strip` |
|---|---|---|---|---|---|---|---|
| `dev` | `0` | `true` | `true` | — | — | `unwind` | — |
| `release` | `3` | `false` | `false` | `fat` | `1` | `abort` | `symbols` |

- **Fat LTO** (`lto = "fat"`) performs link-time optimization across all crates, enabling the compiler to inline and optimize across module boundaries.
- **`codegen-units = 1`** gives LLVM the widest possible view of the program for maximum optimization.
- **`panic = "abort"`** eliminates unwinding landing pads, reducing binary size and preventing use of `std::panic::catch_unwind`.

---

## Code Quality & Linting

All rules are enforced at the workspace level via `[workspace.lints]` in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code              = "forbid"
missing_debug_implementations = "warn"
rust_2018_idioms         = "deny"
elided_lifetimes_in_paths = "warn"

[workspace.lints.clippy]
all      = { level = "deny",  priority = -1 }
pedantic = { level = "warn",  priority = -1 }
unwrap_used = "warn"
expect_used = "warn"
```

- Every `unwrap()` or `expect()` in production code is a compile-time warning — all fallible paths are handled with `Result` and `?`.
- Clippy `all` and `pedantic` lints are denied globally — no exceptions without explicit `#[allow(...)]` annotations with justification.

---

## Workspace Dependencies

All dependency versions are pinned at the workspace level to guarantee consistent builds:

| Crate | Purpose |
|---|---|
| `tokio` (full) | Async runtime — task scheduling, I/O, timers |
| `x25519-dalek` | X25519 ECDH key exchange |
| `ed25519-dalek` | Ed25519 digital signatures |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD cipher |
| `blake2` | Blake2s / Blake2b cryptographic hash |
| `hkdf` | HKDF-SHA-256 key derivation |
| `argon2` | Argon2id password key stretching |
| `zeroize` | Secure memory zeroing for key material |
| `subtle` | Constant-time comparison utilities |
| `snow` | Noise Protocol Framework (IK pattern) |
| `quinn` | QUIC transport (async, TLS 1.3) |
| `igd` | UPnP IGD port mapping |
| `tokio-socks` | SOCKS5 proxy for Tor integration |
| `rcgen` | Self-signed TLS certificate generation (QUIC) |
| `rustls` | Memory-safe TLS 1.3 implementation |
| `serde` + `bincode` | Serialization — binary protocol encoding |
| `prost` | Protocol Buffers (structured messages) |
| `dashmap` | Lock-free concurrent hash map |
| `tracing` | Structured, async-aware logging |
| `thiserror` | Ergonomic `Error` derive macros |
| `rand` | Cryptographically secure random number generation |
| `bip39` | BIP-39 mnemonic phrases |
| `arrayvec` | Fixed-capacity stack-allocated vectors |

---

## Project Status

Zero Protocol is under active development. The core protocol stack (DHT, Onion Routing, Double Ratchet, offline storage, and the packet event loop) is fully implemented. Mobile API bindings and the push / bridge tools are in progress.

| Component | Status |
|---|---|
| `zero-crypto` | ✅ Complete |
| `zero-dht` | ✅ Complete |
| `zero-session` | ✅ Complete |
| `zero-net` | ✅ Complete |
| `zero-onion` | ✅ Complete |
| `zero-offload` | ✅ Complete |
| `zero-core` | ✅ Complete |
| `zero-api` (UniFFI) | ✅ Complete |
| `zero-cli` | ✅ Complete |
| `zero-bootstrap` | ✅ Complete |
| `zero-push` | ✅ Complete |
| `zero-bridge` | ✅ Complete |

---

*Zero Protocol — Private by design. Decentralized by architecture. Secure by default.*
