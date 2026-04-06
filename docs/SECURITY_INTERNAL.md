# Sibna Protocol: Security Assumptions & Attacker Model 🛡️

## 1. Adversary Definition

We define the adversary $\mathcal{A}$ based on two primary profiles:

### Profile A: Global Passive Adversary (GPA)
$\mathcal{A}_{GPA}$ is capable of:
1.  **Full Traffic Eavesdropping**: Observation of all IP packets, sizes, and timestamps across the entire network.
2.  **Metadata Correllation**: Correlating the frequency of communication between specific IP endpoints over extended periods (months/years).

**Our Invariant**: $\mathcal{A}_{GPA}$ should NOT be able to distinguish between an idle session (Cover Traffic only) and an active one (Real encrypted payloads) with non-negligible advantage, given sufficiently high Poisson distribution density for dummy messages.

### Profile B: Active Man-In-The-Middle (MITM)
$\mathcal{A}_{MITM}$ is capable of:
1.  **Injection/Dropping**: Adding or deleting arbitrary packets.
2.  **Impersonation**: Serving forged PreKey bundles during X3DH.

**Our Invariant**: $\mathcal{A}_{MITM}$ cannot succeed in a key-substitution attack without simultaneously breaking the **BLAKE3 Transcript Binding** or the **Ed25519 Identity Signature**. In verified mode, $\mathcal{A}_{MITM}$ is physically neutralized by out-of-band fingerprint comparison.

---

## 2. Security Assumptions

The security of Sibna $S$ relies on the following cryptographic assumptions:

1.  **Gap-Diffie-Hellman (GDH)**: Specifically for the X25519 curve, ensuring the hardness of calculating $abG$ given $aG$ and $bG$ in the random oracle model.
2.  **ML-KEM Correctness & Decapsulation Safety**: We assume ML-KEM-768 is IND-CCA2 secure.
3.  **Hybrid Robustness**: We assume the session key remains secure if AT LEAST ONE of $\{X25519, ML-KEM-768\}$ remains unbroken (Classical vs Quantum security).
4.  **KDF Entropy**: HKDF-SHA256 correctly extracts and expands entropy from the hybrid shared secret.

---

## 3. Engineering Mitigations vs. Formal Proofs

| Concept | Engineering Mitigation | Formal Proof Status |
|---------|------------------------|---------------------|
| **Side-Channel** | `subtle` Constant-Time (CT) arithmetic | **NOT PROVEN** (Compiler/Hardware branches possible) |
| **Memory Security** | `Zeroize` crate on `drop()` | **BEST-EFFORT** (No formal proof against LLVM optimization leaks) |
| **Traffic Analysis** | Random Padding & Poisson Dummy Traffic | **EMPIRICAL** (Heuristic noise, not absolute statistical zero) |
| **Handshake State** | Double Ratchet Finite State Machine | **MODELED** (Signal Protocol logic, not formally verified via TLA+ in this impl) |

## 4. Verdict Realignment

As per the technical critique (April 2026), Sibna v3.0.0 is classified as an **Advanced Experimental Hardened System**. 

- **Confidence level**: High (for mitigation of known commodity attacks).
- **Security level**: Research-Grade (approaching formal correctness but lacking full symbolic verification).
- **Target environment**: Privacy-conscious applications requiring quantum resistance and heavy metadata obfuscation. NOT for governmental secrets or life-critical intelligence without a full tier-1 external audit.
