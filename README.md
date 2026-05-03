# SMQTT

*Pronounced "Smoked It"*

SMQTT is an authenticated pub/sub data broker that lets users securely exchange
encrypted data packets with each other. It is intentionally generic: it knows
nothing about what the data contains, and is designed to stay that way.

SMQTT is for user-to-user encrypted data exchange where the server operator
shouldn't be able to read the content. It adds a layer that vanilla MQTT doesn't
have: user accounts, explicit Relationships as authorization grants, DH key
exchange, JWT-gated topic access, and unguessable topic names.

But otherwise, it has a lot of the upsides of MQTT: pub/sub,
topic-based routing, QoS levels, persistent sessions, and standard MQTT client
libraries on every platform.

## What it does

SMQTT manages users, devices, and Relationships. A Relationship is a permission
grant between two users that controls who can publish and subscribe to whose
topics. All data exchanged through SMQTT is end-to-end encrypted by the clients
before it reaches the broker. SMQTT routes opaque blobs it cannot read.

## What it doesn't do

- Store or inspect data payloads
- Know what kind of data clients are exchanging
- Hold encryption keys
- Retain relationship metadata beyond what is operationally necessary

## Architecture

SMQTT is a Rust application with [rmqtt](https://github.com/rmqtt/rmqtt)
embedded as a library. It runs as a single binary.

```
┌─────────────────────────────────────┐
│               SMQTT                 │
│                                     │
│  ┌─────────────┐  ┌──────────────┐  │
│  │  REST API   │  │  MQTT Broker │  │
│  │             │  │   (rmqtt)    │  │
│  │  - users    │  │              │  │
│  │  - devices  │  │  routes      │  │
│  │  - relations│  │  encrypted   │  │
│  │  - key xchg │  │  blobs       │  │
│  └──────┬──────┘  └──────────────┘  │
│         │ issues JWTs with          │
│         │ topic permissions         │
└─────────────────────────────────────┘
```

On connect, each device authenticates with a JWT. The JWT encodes which topics
that device may publish and subscribe to, derived from the user's current
Relationships.

## Privacy model

**Cryptographic guarantees (not policy):**
- The server never sees plaintext data payloads — clients encrypt before
  publishing
- The server never holds encryption keys — keys are derived from
  Diffie-Hellman shared secrets the server never sees, established out-of-band
  or brokered through SMQTT

**Policy commitments (open source, verifiable):**
- The server does not log or retain relationship metadata beyond active sessions
- The server discards ephemeral key exchange material immediately after delivery

**What the server unavoidably knows:**
- Which accounts exist
- Which devices are connected to which
- Connection patterns (who is active when)

SMQTT does not have a way to hide the social graph from the server operator and
adding that is not on the roadmap.


## Key exchange

Clients establish a shared secret via Diffie-Hellman before exchanging data.
SMQTT offers two paths:

**Server-mediated:** SMQTT brokers the DH public key exchange between two users.
The server learns that the two users are establishing a Relationship, then
discards the key material. It learns nothing further.

**Out-of-band (invite link / QR code):** The client app generates an invite link
containing an ephemeral DH public key. The user shares it via any channel. The
server is never involved. This is the stronger privacy option.

Both paths produce the same result: a shared secret on each device, from which
topic names and encryption keys are derived.

## Topic naming

Topic names are derived from the shared secret established during key exchange.
This makes them unguessable to third parties who do not hold the shared secret,
even if they are connected to the broker.

## Building

```
cargo build --release
```

## Running

```
./target/release/smqtt --config smqtt.toml
```

## Development

Fuzzing (not pushed yet) required Rust's nightly compiler:

```
rustup default nightly
```

## Clients

SMQTT is the server component of [Surveil
Whence](https://github.com/jamesvasile/surveil-whence), a privacy-respecting
location sharing app. Any client that implements the SMQTT key exchange and
topic derivation conventions can use it.
