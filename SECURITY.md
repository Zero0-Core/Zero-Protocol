# Security Model & Threat Analysis

Zero Protocol is designed from the ground up to be a resilient, anonymous, and peer-to-peer messaging system. This document outlines the security guarantees, the threat model, and known limitations of the current implementation.

## 1. Core Security Guarantees

*   **End-to-End Encryption (E2EE)**: Every session message is encrypted using the Signal Double Ratchet algorithm, ensuring both forward secrecy and post-compromise recovery.
*   **Anonymity via Unidirectional Onion Routing**: Separate outbound/inbound ephemeral circuits (3 hops each) obscure the source and destination.
*   **Metadata Resistance**: 
    *   IP addresses are hidden behind **LeaseSet Gateways**.
    *   Packet sizes are perfectly obscured using **2048-byte constant-size padding** (Chaff).
*   **Zero-Knowledge Storage**: Offline message blobs are encrypted with the recipient's public key; storage nodes cannot see the content, sender, or recipient identity.
*   **Decentralized Trust**: No central authority or bootstrap servers hold any user data or keys.

---

## 2. Threat Model

### 2.1 Adversary Capabilities

We assume an adversary may:
1.  Observe all network traffic (ISP level).
2.  Control a percentage of nodes in the DHT (Sybil attack).
3.  Operate malicious relay/onion nodes.
4.  Capture a user's device (Local storage access).

### 2.2 Mitigations

| Threat | Mitigation | Implementation Status |
|---|---|---|
| **Traffic Analysis** | Unidirectional Onion Routing + 2048-byte constant-size padding. | ✅ Implemented |
| **Sybil Attack** | Anti-Sybil subnet diversity rules (max 2 nodes per /24 subnet per k-bucket). | ✅ Implemented |
| **Key Compromise** | Double Ratchet rotates symmetric keys per message; local storage encrypted via Argon2id. | ✅ Implemented |
| **Denial of Service** | Per-IP token-bucket rate limiting (100 packets/sec) on all entry points. | ✅ Implemented |
| **Spam / Flooding** | Blake2s Proof-of-Work required for offline store-and-forward requests. | ✅ Implemented |

---

## 3. Cryptographic Implementation

*   **Handshake**: Noise IK (Curve25519, ChaChaPoly, BLAKE2s).
*   **Key Derivation**: HKDF-SHA256 with strict domain separation.
*   **Symmetric Encryption**: ChaCha20-Poly1305 (Authenticated Encryption).
*   **Identity**: X25519 (for sessions) and Ed25519 (for signing offline blobs).
*   **Local Storage**: Argon2id for password-based key stretching.

---

## 4. Known Limitations & Future Work

While Zero Protocol is "Hardened," the following areas are identified for future security research:

1.  **Global Passive Adversary**: A sophisticated adversary observing the *entire* internet is forced into high-cost statistical analysis, as unidirectional paths and constant padding eliminate simple timing/size correlation.
2.  **Quantum Resistance**: Current primitives (X25519, Ed25519) are not quantum-resistant. Future versions will explore Kyber/Dilithium hybrid handshakes.
3.  **Bootstrap Centralization**: Initial bootstrap relies on a hardcoded list of nodes. While distributed, this remains a potential target for blocking. DNS-over-HTTPS (DoH) bootstrap is under evaluation.
4.  **Traffic Correlation**: Very long sessions between the same two IPs (in `Direct` mode) may allow an observer to infer a social relationship even if content is hidden.

## 5. Security Audit Status

Zero Protocol systematic audit history:
*   **Internal Audit**: May 2026 (Memory safety, Crypto primitive validation, Protocol logic).
*   **External Audit**: Pending.

*Zero Protocol — Formally auditable. Safe by design.*
