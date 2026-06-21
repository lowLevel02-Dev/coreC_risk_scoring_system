# ZeroTrustEngine — Core C Risk Scoring Engine

> **Component:** Layer 1 — Runtime Decision Core  
> **Language:** C (C11 standard)  
> **Build Output:** `libriskscore.so` — shared library consumed by the application backend via FFI

---

## Overview

ZeroTrustEngine is a high-performance, real-time behavioural risk scoring engine written in pure C. It serves as the central decision authority in a collaborative Zero Trust Access Control system — every security judgment (allow, restrict, demand MFA, or block) originates from this library.

The engine is compiled as a shared object and loaded in-process by the backend application via `ctypes` or `cffi`. It evaluates every authentication event and in-session API action, maintains per-user behavioural baselines, and returns a calibrated risk decision within a single function call.

### Capabilities at a Glance

| Capability | Implementation |
|---|---|
| Rule-based risk scoring | Weighted formula over time-of-day, device, location, and failed attempts |
| Per-user behavioural profiling | Welford's online statistics — running mean and variance, zero history storage |
| Device & location memory | Bloom filter — privacy-preserving, no raw identifiers stored |
| In-session event tracking | Fixed-size circular ring buffer (16 events) per session |
| Risk velocity tracking | Rate of score change, not just absolute score |
| Trust decay | Score drifts back toward zero during normal behaviour on each periodic tick |
| Isolation Forest inference | Pure-C loader and inference engine for pre-trained anomaly detection models |
| Token bucket rate limiting | Per-user and per-IP request throttling |
| HMAC validation | Session and audit integrity verification via OpenSSL SHA-256 |
| Constant-time comparison | Timing-safe comparison to prevent timing side-channel attacks |
| Profile serialization | Binary serialization of `UserProfile` for database persistence and reload |
| Thread safety | All shared state protected by `pthread_rwlock_t` |

---

## System Context

ZeroTrustEngine is **Layer 1** of a four-layer Zero Trust Access Control platform:

```
┌──────────────────────────────────────────────────────────┐
│  Layer 4 — Admin Dashboard & Frontend                    │
│  Layer 3 — FastAPI Application Backend + FFI Bridge      │
│  Layer 2 — ML Training Pipeline (Isolation Forest)       │
│  Layer 1 — Core C Risk Scoring Engine  ◄ this repo       │
└──────────────────────────────────────────────────────────┘
```

The public API header `risk_engine.h` is the **frozen contract** between Layer 1 and all upstream layers. The backend FFI bridge is built entirely against this header.

---

## Repository Structure

```
ZeroTrustEngine/
├── CMakeLists.txt          # Build system — produces libriskscore.so
├── include/
│   ├── risk_engine.h       # ★ Public API — frozen interface contract
│   ├── model.h             # IsolationForest and IsoNode structs, loader API
│   ├── profile.h           # UserProfile bloom filter and serialization API
│   ├── session.h           # SessionBuffer ring buffer API
│   ├── scoring.h           # Internal scoring function declarations
│   └── security.h          # TokenBucket, HMAC, constant-time compare
├── src/
│   ├── risk_engine.c       # Engine lifecycle, evaluate_login, evaluate_event
│   ├── scoring.c           # Rule-based scoring weights + ML feature vector
│   ├── profile.c           # Welford statistics, bloom filter, serialization
│   ├── session.c           # Ring buffer push, velocity computation
│   ├── model.c             # Binary model loader, CRC32 validation, IF inference
│   └── security.c          # Token bucket, HMAC (OpenSSL), constant-time XOR
└── build/
    └── libriskscore.so     # Compiled shared library
```

---

## Public API — `risk_engine.h`

This file is the single source of truth for every upstream integration. All signatures are frozen.

### Enumerations

```c
typedef enum { LOW, MEDIUM, HIGH, CRITICAL }             RiskLevel;
typedef enum { ALLOW, RESTRICT, MFA_REQUIRED, BLOCK }   DecisionType;
typedef enum { LOGIN, API_CALL, FILE_DOWNLOAD,
               PASSWORD_CHANGE, ADMIN_ACTION,
               DATA_EXPORT, FAILED_AUTH }                EventType;
```

### Key Structs

| Struct | Purpose |
|---|---|
| `LoginEvent` | Input to `re_evaluate_login` — user ID, timestamp, device hash, IP hash, geo hash, failed attempts |
| `SessionEvent` | Input to `re_evaluate_event` — session ID, user ID, event type, timestamp, bytes transferred, endpoint hash |
| `RiskDecision` | Output of both evaluate calls — decision, risk level, combined score, rule score, ML score, reason code |
| `UserProfile` | Per-user running statistics — Welford mean/variance for login hour and bytes, login count, bloom filter (256 bytes), current risk score |
| `EngineConfig` | Startup configuration — model path, MFA/block thresholds, decay rate, tick interval, max users |

### Engine Lifecycle

```c
RiskEngine* re_engine_create(const EngineConfig* config);
void        re_engine_destroy(RiskEngine* engine);
int         re_engine_reload_model(RiskEngine* engine, const char* model_path);
void        re_engine_tick(RiskEngine* engine);   // call periodically for trust decay
```

### Evaluation

```c
RiskDecision re_evaluate_login(RiskEngine* engine, const LoginEvent* event);
RiskDecision re_evaluate_event(RiskEngine* engine, const SessionEvent* event);
```

### Profile Persistence

```c
int re_profile_serialize  (RiskEngine* engine, uint64_t user_id,
                            uint8_t* out_buf, uint32_t buf_size, uint32_t* written);
int re_profile_deserialize(RiskEngine* engine,
                            const uint8_t* buf, uint32_t buf_size);
```

### Security Utilities

```c
int re_hmac_validate       (const uint8_t* key,  uint32_t key_len,
                             const uint8_t* data, uint32_t data_len,
                             const uint8_t* expected_hmac);
int re_constant_time_compare(const uint8_t* a, const uint8_t* b, uint32_t len);
```

---

## Scoring Logic

### Login Score — `re_evaluate_login`

The final score is a **60/40 blend** of the rule-based score and the ML anomaly score:

```
final_score = (rule_score × 0.60) + (ml_score × 0.40)
```

When no model file is loaded, `ml_score` is `0.0` and the engine operates in rule-only mode — a safe, fully functional fallback.

The rule-based component is a **weighted sum** of four signals:

| Signal | Weight | Score Range |
|---|---|---|
| Time of day | 0.25 | 0.0 (09:00–18:00) → 0.3 (18:00–22:00) → 0.5 (06:00–09:00) → 1.0 (22:00–06:00) |
| Failed authentication attempts | 0.30 | 0.0 (0) → 0.3 (1–2) → 0.7 (3–4) → 1.0 (≥ 5) |
| Unrecognised device | 0.25 | 0.0 if bloom filter reports known, 1.0 if new device |
| Unrecognised location | 0.20 | 0.0 if bloom filter reports known, 0.5 if new geo-hash |

### In-Session Event Score — `re_evaluate_event`

```
final_score = base_event_score + (velocity × 0.30)
```

Base scores by event type:

| Event Type | Base Score |
|---|---|
| `API_CALL` | 0.0 |
| `LOGIN` | 0.1 |
| `FILE_DOWNLOAD` | 0.2 |
| `PASSWORD_CHANGE` | 0.3 |
| `ADMIN_ACTION` | 0.4 |
| `DATA_EXPORT` | 0.5 |
| `FAILED_AUTH` | 0.6 |

### Decision Thresholds (configurable via `EngineConfig`)

| Score Range | Decision |
|---|---|
| `< score_threshold_mfa` | `ALLOW` |
| `[threshold_mfa, threshold_block)` | `MFA_REQUIRED` |
| `≥ score_threshold_block` | `BLOCK` |

---

## Behavioural Profiling — Welford's Online Algorithm

Each `UserProfile` maintains a **running mean and variance** of the user's login hour without storing any historical records. This is Welford's single-pass online algorithm:

```c
delta     = new_value - mean;
mean     += delta / count;
delta2    = new_value - mean;
variance += delta * delta2;
```

The baseline is always current with zero memory overhead beyond two `double` values per tracked statistic. The profile also tracks `bytes_per_session_mean` and `bytes_per_session_variance` for downstream ML feature construction.

---

## Bloom Filter — Privacy-Preserving Device & Location Memory

The 256-byte bloom filter embedded in each `UserProfile` uses **three independent hash functions** to store device hashes and geo-hashes:

```c
i1 = hash % 2048
i2 = (hash >> 11) % 2048
i3 = (hash * 2654435761UL) % 2048   // Knuth multiplicative hash constant
```

Raw device identifiers and IP addresses are never stored inside the engine. Only the bit positions derived from their hashes are set. This provides a provable privacy guarantee: you cannot reconstruct the original identifier from the bloom filter state.

---

## Risk Velocity

The session ring buffer retains the last 16 events per session. Velocity is computed on each event as:

```
velocity = (current_score − last_score) / elapsed_seconds
```

A score that escalates from `0.2 → 0.7` in 30 seconds produces a velocity of `0.0167/s`, adding a velocity penalty of `0.005` to the final score — amplifying the alarm signal of rapid escalations. A stable score of `0.7` reached over an hour produces negligible velocity contribution.

---

## Trust Decay

`re_engine_tick()` applies **exponential decay** to every user's current risk score on each call:

```c
profile->current_risk_score *= (1.0f - config->decay_rate);
```

With a `decay_rate` of `0.05`, a score of `0.8` decays to approximately `0.36` after 20 ticks. The backend should invoke `re_engine_tick` from a background thread at the cadence configured in `tick_interval_sec`. This ensures the system does not permanently penalise users for historical anomalies once behaviour normalises.

---

## Isolation Forest Inference (Pure C)

### Binary Model Format

The `model.isof` binary file format uses a 32-byte header followed by a flat array of `IsoNode` structs. The engine validates integrity via CRC32 before loading.

**Header layout:**

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 4 | `magic` | `0x464F5349` — ASCII "ISOF" in little-endian |
| 4 | 4 | `version` | Format version number |
| 8 | 4 | `tree_count` | Number of isolation trees |
| 12 | 4 | `feature_count` | Must equal `6` (validated on load) |
| 16 | 4 | `data_offset` | Byte offset to the start of node data |
| 20 | 4 | `checksum` | CRC32 over all bytes from offset 32 onward |
| 24 | 8 | _(reserved)_ | Alignment padding |
| 32 | N × 28 | `IsoNode[]` | Flat node array — all trees concatenated |

**`IsoNode` struct (28 bytes):**

```c
typedef struct {
    uint32_t node_id;        // 0 identifies the root node of each tree
    uint32_t left_child;     // offset from tree root; 0xFFFFFFFF = leaf sentinel
    uint32_t right_child;
    uint32_t feature_index;  // index into the 6-element feature vector
    float    threshold;      // split threshold
    float    path_length;    // depth accumulated at leaf nodes
} IsoNode;
```

### Feature Vector Specification

The 6-element `float` feature vector constructed at login evaluation time:

| Index | Feature | Normalisation |
|---|---|---|
| 0 | Login hour of day | `hour / 23.0` |
| 1 | Failed authentication attempts | `count / 10.0` |
| 2 | Device hash signal | `(device_hash % 1000) / 1000.0` |
| 3 | Geo-hash signal | `(geo_hash % 1000) / 1000.0` |
| 4 | IP hash signal | `(ip_hash % 1000) / 1000.0` |
| 5 | Historical login depth | `login_count / 100.0` |

### Anomaly Score Formula

The engine implements the standard Isolation Forest anomaly score:

$$s(x, n) = 2^{-\frac{E[h(x)]}{c(n)}}$$

where $c(n) = 2(\ln(n-1) + \gamma) - \dfrac{2(n-1)}{n}$, $\gamma = 0.5772156649$ (Euler–Mascheroni constant), and $n = 256$ (subsample size assumed during training).

---

## Security Utilities

### Token Bucket Rate Limiter

```c
void token_bucket_init   (TokenBucket* bucket, float capacity, float refill_rate);
int  token_bucket_consume(TokenBucket* bucket, int64_t current_time);
// Returns 1 — request allowed   |   0 — request throttled
```

Tokens refill at `refill_rate` tokens per second up to `capacity`. Invoke `token_bucket_consume` before processing each incoming request. Each engine instance may maintain independent `TokenBucket` objects for per-user and per-IP rate limiting.

### HMAC Validation

```c
int re_hmac_validate(key, key_len, data, data_len, expected_hmac);
// Returns 0 — HMAC matches   |   -1 — mismatch or computation error
```

Computes HMAC-SHA256 via OpenSSL and compares the result using `re_constant_time_compare` to prevent timing leakage during verification.

### Constant-Time Comparison

```c
int re_constant_time_compare(const uint8_t* a, const uint8_t* b, uint32_t len);
// Returns 0 if equal — execution time does NOT vary with string content
```

Implemented as a bitwise XOR accumulator over all bytes with no short-circuit branching. All byte positions are always evaluated regardless of where a mismatch occurs, preventing timing side-channel attacks.

---

## Build Instructions

### Prerequisites

- GCC with C11 support
- CMake ≥ 3.16
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on RHEL)
- POSIX threads (`pthreads`, included in glibc)

### Build

```bash
mkdir build && cd build
cmake ..
make
```

Output: `build/libriskscore.so`

### Run Test Binary

```bash
./build/test_engine
```

### Valgrind Memory Check

```bash
valgrind --leak-check=full --track-origins=yes --error-exitcode=1 ./build/test_engine
```

---

## Backend FFI Integration Guide

The backend loads the shared library via `ctypes`. C structs must be mirrored exactly — field order, types, and sizes must match byte-for-byte.

```python
import ctypes

lib = ctypes.CDLL("./build/libriskscore.so")

class LoginEvent(ctypes.Structure):
    _fields_ = [
        ("user_id",         ctypes.c_uint64),
        ("timestamp_unix",  ctypes.c_int64),
        ("device_hash",     ctypes.c_uint64),
        ("ip_hash",         ctypes.c_uint32),
        ("geo_hash",        ctypes.c_uint32),
        ("failed_attempts", ctypes.c_uint8),
    ]

class RiskDecision(ctypes.Structure):
    _fields_ = [
        ("decision",    ctypes.c_int),    # DecisionType enum
        ("risk_level",  ctypes.c_int),    # RiskLevel enum
        ("score",       ctypes.c_float),
        ("reason_code", ctypes.c_uint32),
        ("ml_score",    ctypes.c_float),
        ("rule_score",  ctypes.c_float),
    ]

lib.re_evaluate_login.restype  = RiskDecision
lib.re_evaluate_login.argtypes = [ctypes.c_void_p, ctypes.POINTER(LoginEvent)]
```

### Profile Persistence Pattern

The backend should persist `UserProfile` to the database after every login (so the behavioural baseline survives server restarts) and restore it before evaluating the next login for that user.

```python
# After login — serialize and store
buf = (ctypes.c_uint8 * SIZEOF_USER_PROFILE)()
written = ctypes.c_uint32(0)
lib.re_profile_serialize(engine, user_id, buf, SIZEOF_USER_PROFILE, ctypes.byref(written))
db.store_profile(user_id, bytes(buf[:written.value]))

# Before next login — restore from database
blob = db.load_profile(user_id)
buf  = (ctypes.c_uint8 * len(blob))(*blob)
lib.re_profile_deserialize(engine, buf, len(blob))
```

> **Note:** `SIZEOF_USER_PROFILE` is `ctypes.sizeof(UserProfile_ctypes_struct)`. This value must be used as the `bytea` column size constraint in the database schema.

---

## Thread Safety

The opaque `RiskEngine` struct contains a single `pthread_rwlock_t`. Lock acquisition per function:

| Function | Lock Mode | Reason |
|---|---|---|
| `re_evaluate_login` | Write | Mutates `UserProfile` (Welford update, bloom add) |
| `re_evaluate_event` | Write | Mutates `SessionBuffer` and `UserProfile.current_risk_score` |
| `re_profile_serialize` | Read | Read-only access to `UserProfile` |
| `re_profile_deserialize` | Write | Inserts or updates `UserProfile` slot |
| `re_engine_tick` | Write | Decays all profiles |
| `re_engine_reload_model` | Write | Atomically swaps the `IsolationForest` model |

Multiple backend worker threads may call any public function concurrently — the rwlock correctly serialises all mutations.

---

## Dependencies

| Dependency | Minimum Version | Purpose |
|---|---|---|
| GCC / Clang | C11 | Compilation |
| CMake | 3.16 | Build orchestration |
| OpenSSL (`libcrypto`) | 1.1 | HMAC-SHA256 computation |
| pthreads | POSIX | Reader-writer locking |
| libm | System | `log`, `pow` for Isolation Forest anomaly score |

---

## Completed Implementation Stages

- [x] **Stage 1** — `risk_engine.h` public API header (frozen interface contract)
- [x] **Stage 2** — Rule-based scoring engine (`scoring.c`, `risk_engine.c`)
- [x] **Stage 3** — Welford per-user profiling, bloom filter, profile serialization (`profile.c`)
- [x] **Stage 4** — Session ring buffer, risk velocity, trust decay (`session.c`, `re_engine_tick`)
- [x] **Stage 5** — Isolation Forest binary model loader and C inference engine (`model.c`)
- [x] **Stage 6** — Token bucket rate limiter, constant-time comparison, HMAC validation (`security.c`)
- [x] **Build** — `libriskscore.so` compiles and links cleanly via CMake

---

## License

This component is part of a group academic project. All rights reserved by the respective authors.
