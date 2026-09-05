# Argos Sniffer v6 — Sensor Enrichment Backlog

This is a planning-only companion backlog for passive sensor capabilities that can increase fingerprint value without turning Argos Sniffer into a heavy DPI engine.

It is intentionally non-disruptive: no item in this document authorizes packet-loop, state-owner, dispatcher, CLI, suppression/dedup or telemetry-contract changes while those contracts are still moving in the active v6 refactor. Before implementation, re-read the current `version-6` source and reconcile each item with `V6_BACKLOG.md`.

## Design rule

Argos Sniffer should become a better sensor, not a larger intelligence database.

The sniffer should extract small bounded observations. Application identity, behavior baselines, relationship graphs, ASN/infrastructure intelligence, long-term correlation and ML belong in the collector.

Do not add:

- generic full DPI;
- full stream/session storage;
- cloud lookups in the packet path;
- thousands of application signatures inside C;
- ML inference inside the sniffer;
- automatic active scanning by default;
- unbounded per-flow state.

## Priority 1 — TLS server-side fingerprint enrichment

### Goal

Extend the current TLS observation model beyond ClientHello/SNI/JA4/ALPN with bounded server-side metadata that is useful for passive device and service fingerprinting.

### Candidate observations

- ServerHello protocol version;
- negotiated cipher suite;
- selected ALPN;
- server-side TLS fingerprint suitable for JA4S-style correlation;
- TLS extension presence/count where useful;
- HelloRetryRequest presence;
- session resumption indicator when passively observable;
- TLS 1.3 early-data / 0-RTT indication when passively observable;
- ECH presence/attempt indication from ClientHello metadata where observable without decryption.

### Certificate-lite candidate metadata

Only if it can be collected with bounded work and without retaining certificate bodies:

- certificate-present boolean;
- leaf subject CN/SAN summary only if safely bounded;
- issuer summary only if safely bounded;
- validity duration or not-before/not-after summary;
- self-signed indicator;
- compact certificate fingerprint/hash if useful for correlation.

Never emit or retain full certificate chains in the hot path.

### Constraints

- no full TLS stream reconstruction merely for these fields;
- no heap allocation in normal packet handling;
- fixed maximum inspected bytes;
- stop inspection immediately after required handshake evidence is complete;
- no certificate body telemetry;
- no private-key/session-key material;
- preserve existing ClientHello/JA4 behavior until a separately gated schema migration.

### Pre-implementation work

- [ ] Audit current `argos_tls.h` ServerHello coverage against these candidate fields.
- [ ] Decide whether JA4S is implemented exactly or represented as an Argos server fingerprint; document compatibility implications.
- [ ] Build sanitized TLS 1.2/TLS 1.3 ServerHello fixtures.
- [ ] Add HelloRetryRequest fixture.
- [ ] Add ECH-present ClientHello fixture where the marker is observable.
- [ ] Add resumption/PSK fixture.
- [ ] Add 0-RTT/early-data fixture.
- [ ] Define maximum bytes and maximum packets inspected per TLS direction.
- [ ] Define exact fast-complete condition for client and server TLS evidence.
- [ ] Benchmark text size and packet-loop impact before runtime promotion.

## Priority 1 — Protocol fast-complete / fast-drop matrix

### Goal

Formalize when each protocol engine has collected all useful fingerprint metadata so Argos stops inspecting bulk traffic immediately.

This is more important than deeper DPI for elephant-flow protocols.

### Required matrix fields

For each production or staged protocol document:

| Field | Meaning |
|---|---|
| protocol | canonical protocol name |
| trigger | minimal L2/L3/L4/port/magic condition |
| evidence packet(s) | which initial control/handshake messages matter |
| complete condition | exact point after which no more fingerprint value is expected |
| drop condition | malformed/unsupported/bulk condition that stops inspection |
| max packets | hard packet inspection ceiling per flow/direction |
| max bytes | hard byte inspection ceiling |
| state bytes | maximum per-flow state required |
| timeout | bounded state lifetime |
| identity value | whether identity metadata can appear before completion |
| privacy check | fields that must never be emitted |

### Initial protocol families to audit

- TLS / DoT;
- QUIC Initial;
- HTTP / HTTP proxy;
- SMB / NTLM;
- NFS / SunRPC;
- RDP / SSH;
- database handshakes;
- LDAP / LDAPS;
- RTSP / RTP / RTCP;
- Syslog / NetFlow / IPFIX / sFlow — production header-only budgets verified;
- industrial control protocols;
- VPN control protocols.

### Acceptance rule

A new protocol is not considered integrated until its fast-complete/drop budget is documented and tested.

### Pre-implementation work

- [ ] Produce protocol-by-protocol fast-complete matrix from current source and staging parsers.
- [ ] Identify engines that currently continue parsing after fingerprint value is exhausted.
- [ ] Identify elephant-flow exposure points.
- [ ] Define regression fixtures proving post-completion payload does not change the observation.
- [ ] Add performance benchmark cases with long bulk tails after a short identifying handshake.

## Priority 2 — Bounded flow-shape fingerprint

### Goal

Provide a small optional fingerprint for encrypted/ECH traffic using only the shape of the first packets of a flow.

This is evidence only. It must never become an application classifier inside the sniffer.

### Candidate bounded observation

A flow-shape record may contain only a fixed-size prefix such as:

- transport;
- direction of first packet;
- packet count observed in each direction up to a hard cap;
- byte count in each direction up to completion;
- first N payload lengths per direction;
- first N direction transitions;
- coarse handshake duration bucket;
- optional inter-arrival buckets, only if measurement cost is proven negligible.

Suggested starting ceiling for evaluation, not implementation contract:

- first 4 payload-bearing packets per direction;
- 8 stored packet-length values total;
- 16-bit saturated lengths/counters where possible;
- no payload bytes retained;
- no dynamically allocated state.

### Example semantic record

```text
FLOW-SHAPE|
transport=tcp
up_packets=4
down_packets=4
up_sizes=128,517,74,1430
down_sizes=91,1430,1430,1430
transitions=5
```

Exact telemetry syntax is deliberately not frozen here.

### Constraints

- disabled by default until measured;
- fixed-size state only;
- no payload storage;
- no ML/scoring in sniffer;
- collector owns correlation/classification;
- state must expire independently of protocol parsers;
- do not create a second generic flow tracker if existing bounded state can own it cleanly.

### Pre-implementation work

- [ ] Audit current bounded TCP/UDP state to determine whether flow-shape can reuse ownership without coupling lifetimes.
- [ ] Calculate state cost for 128/256/512/1024 concurrent tracked flows.
- [ ] Evaluate 2, 4 and 8 packet samples per direction for fingerprint value versus memory cost.
- [ ] Define saturation and truncation behavior.
- [ ] Create deterministic fixture format for direction/size sequences.
- [ ] Benchmark packets/sec and cache impact with feature disabled and enabled.
- [ ] Reject the feature if disabled-mode cost is measurable or enabled-state cost is disproportionate.

## Priority 2 — Normalized observation metadata

### Goal

Keep protocol engines focused on bounded extraction and make emitted evidence easier for the collector to correlate later.

### Candidate semantic fields

Where naturally observable, protocol engines may expose:

- protocol;
- role: client/server/peer/controller/agent/exporter;
- phase: discovery/handshake/auth/control/data;
- capability flags;
- application identity string when directly present on wire;
- username/principal/machine identity under existing privacy rules;
- server/product banner when bounded and passive;
- fingerprint hash/id;
- completion reason: complete/truncated/unsupported/malformed.

These are observation fields, not packet-view fields.

### Constraints

- do not change telemetry grammar until the canonical schema phase permits it;
- do not duplicate collector-side classification;
- no confidence scoring inside individual parsers unless existing architecture explicitly owns it there;
- preserve protocol-specific evidence rather than forcing every engine into a lossy generic schema.

### Pre-implementation work

- [ ] Build a cross-protocol observation-field inventory.
- [ ] Identify duplicate semantic fields with inconsistent names.
- [ ] Propose canonical names without changing runtime output.
- [ ] Mark protocol-private fields that must remain protocol-specific.
- [ ] Map future collector correlation needs back to the minimum sensor evidence required.

## Priority 3 — Targeted active-enrichment hook

### Goal

Preserve a future path for passive-first, narrowly targeted active enrichment without making the sniffer an active scanner.

### Principle

```text
high passive confidence -> no probe
medium confidence       -> wait for more passive evidence
low confidence          -> optional targeted probe, policy-controlled
```

### Candidate future probes

Outside the passive packet path and default OFF:

- IPP metadata query for suspected printers;
- HTTP HEAD/metadata request for management interfaces;
- UPnP device description retrieval;
- SNMP sysDescr/sysObjectID only when explicitly configured and credentials/community policy exists outside telemetry;
- protocol-native safe metadata probes where a specific device class justifies them.

### Constraints

- no generic automatic nmap/service scan as part of this hook;
- no credentials inside sniffer telemetry;
- strict rate limiting and explicit opt-in;
- separate process/module may be preferable to embedding probe logic into the capture engine;
- implementation must not increase passive hot-path cost when disabled.

### Pre-implementation work

- [ ] Define an abstract probe request/result contract only after v6 telemetry/config contracts freeze.
- [ ] Decide whether the sniffer should merely emit enrichment-needed evidence while another component performs probes.
- [ ] Document safety/rate limits and default-off policy.
- [ ] Keep this after passive v6 release hardening unless a concrete use case justifies earlier work.

## Candidate output / fingerprint contracts

These are **candidate semantic contracts**, not permission to change the current v6 wire format. The final telemetry grammar, escaping and field ordering remain gated by the schema-freeze phase in `V6_BACKLOG.md`.

The objective is to make every staged parser answer four questions before promotion:

1. What evidence does it emit?
2. Which fields form a stable fingerprint?
3. When is the evidence complete?
4. What data must never be emitted?

### TLS client enrichment

Candidate vector: `TLS-CLIENT` or extension of the canonical `TLS` vector after schema freeze.

Required fields:

```text
version=<negotiated-or-client-max>
ja4=<existing-ja4>
alpn=<first-or-selected-client-alpn>
sni=<bounded-sni-or-empty>
```

Optional enrichment fields:

```text
ech=0|1
psk=0|1
psk_modes=<bounded-list-or-count>
early_data=0|1
supported_versions=<bounded-list>
```

Stable fingerprint material:

```text
JA4
+ ALPN class
+ ECH presence
+ PSK/resumption capability
+ supported-version family
```

Do not include SNI in the stable client fingerprint because hostname changes should not change the client implementation identity.

Fast-complete point: after ClientHello extensions required for JA4/SNI/ALPN/ECH/PSK metadata are parsed.

Never emit:

```text
PSK identities
session tickets
early-data payload
key shares/private key material
raw ClientHello body
```

### TLS server / ServerHello enrichment

Candidate vector: `TLS-SERVER` or server-side fields on canonical `TLS`.

Required fields:

```text
version=<negotiated-version>
cipher=<selected-cipher>
ext_count=<non-grease-count>
```

Optional fields:

```text
alpn=<selected-alpn-if-visible>
hrr=0|1
psk_selected=0|1
early_data=0|1
ech=0|1
extensions=<bounded-normalized-extension-list>
```

Stable fingerprint material:

```text
transport + negotiated_version + extension_count + ALPN class
+ selected_cipher + sorted/non-GREASE extension set
```

This material is intentionally suitable for a future JA4S-compatible or Argos-native server fingerprint. Exact JA4S hashing/naming is not frozen here.

Fast-complete point: after ServerHello plus any immediately required bounded handshake metadata used by the selected server fingerprint contract.

Never emit raw key-share bytes, random values, session secrets or handshake bodies.

### TLS certificate framing

Candidate vector: `TLS-CERT` only if certificate evidence remains useful enough to justify a separate vector; otherwise fold into server-side TLS evidence.

Required fields:

```text
present=1
chain_count=<bounded-count>
leaf_len=<bounded-length>
```

Optional fields:

```text
chain_truncated=0|1
```

Stable fingerprint material: none by itself. Framing metadata is an input to certificate-lite extraction, not a long-term device fingerprint.

Fast-complete point: once the leaf certificate range and bounded chain count are known.

Never emit certificate body bytes or the full certificate chain.

### X.509 leaf certificate-lite

Candidate vector: `TLS-CERT` or certificate fields embedded in `TLS-SERVER`.

Required candidate fields when available:

```text
subject_cn=<bounded-cn>
issuer_cn=<bounded-cn>
self_signed=<0|1-hint>
```

Optional fields:

```text
san=<first-bounded-dns-san-values>
san_count=<count>
san_truncated=0|1
not_before=<normalized-time>
not_after=<normalized-time>
cert_hash=<compact-leaf-hash-if-later-approved>
```

Stable fingerprint material:

```text
leaf certificate hash               (strongest, if implemented)
OR
issuer CN + subject CN + bounded SAN set + validity window class
```

The textual tuple is correlation evidence, not a cryptographic identity. A future compact leaf hash should hash only the DER leaf certificate and should never require storing the body after hashing.

Fast-complete point: after the leaf DER range has been bounded and the selected leaf metadata has been extracted.

Never emit:

```text
full DER certificate
full certificate chain
public-key blob unless a future explicit fingerprint requires a bounded hash only
certificate extensions unrelated to device/service fingerprinting
```

### Fast-complete / fast-drop policy

This staging unit does not emit a network vector. Its output is a runtime policy decision.

Candidate internal result:

```text
protocol=<id>
action=continue|complete|drop
reason=fingerprint_complete|bulk_tail|malformed|unsupported|budget_exhausted
packets_seen=<bounded-counter>
bytes_seen=<bounded-counter>
```

Fingerprint contribution: none. The policy protects the fingerprint engines from inspecting traffic after useful evidence is exhausted.

Telemetry should normally **not** expose these fields. Optional debug/performance modes may expose aggregate counters, not per-flow policy spam.

### Bounded flow-shape

Candidate vector: `FLOW-SHAPE` only when explicitly enabled and only if benchmark gates pass.

Required candidate fields:

```text
transport=tcp|udp
first_dir=out|in
up_packets=<saturated-count>
down_packets=<saturated-count>
up_sizes=<fixed-N-list>
down_sizes=<fixed-N-list>
transitions=<saturated-count>
```

Optional fields:

```text
duration_bucket=<coarse-bucket>
interarrival_buckets=<fixed-N-list>
truncated=0|1
```

Stable fingerprint material:

```text
transport
+ first direction
+ fixed prefix of packet-size sequence
+ direction-transition pattern
+ optional coarse timing buckets
```

The stable fingerprint should be encoded from the normalized bounded sequence and may later be hashed by the collector. The sniffer must not perform application classification from it.

Fast-complete point: hard N-packet/N-byte ceiling or timeout, whichever occurs first.

Never emit payload bytes, exact high-resolution timing traces or unbounded packet sequences.

### Normalized observation metadata

Candidate common semantic envelope, not necessarily a literal wire vector:

```text
protocol=<canonical-id>
role=client|server|peer|controller|agent|exporter
phase=discovery|handshake|auth|control|data
fingerprint=<protocol-specific-id-or-empty>
completion=complete|truncated|unsupported|malformed
```

Optional common fields:

```text
capabilities=<bounded-flags>
identity=<allowed-passive-identity>
product=<bounded-product/banner>
```

Protocol-specific fields remain protocol-specific. Do not force all observations into one giant generic key/value object.

### Targeted active-enrichment result

This remains post-v6/default-OFF and should probably be produced by a separate enrichment component rather than the passive capture loop.

Candidate result envelope:

```text
ENRICH|device=<stable-device-key>|probe=<probe-type>|status=<ok|timeout|rejected>|evidence=<bounded-metadata>
```

Fingerprint contribution: active evidence may raise collector confidence, but it must not silently overwrite passive fingerprint evidence.

Never emit credentials, secrets, write-capable probe results or arbitrary response bodies.

## Output/fingerprint promotion rule

No staged enrichment parser is ready for production until all of the following are defined and tested:

- canonical vector owner;
- required/optional fields;
- maximum length for every string/list field;
- deterministic ordering for fingerprint inputs;
- GREASE/noise exclusion rules where applicable;
- fingerprint stability test: irrelevant session changes do not change the fingerprint;
- discrimination test: meaningful implementation/server changes can change the fingerprint;
- exact fast-complete condition;
- privacy exclusion assertions;
- collector compatibility fixture;
- malformed/truncated fixture;
- native + sanitizer + ARM64 gate;
- text-size and packet-path performance gate.

## Proposed sequencing relative to `V6_BACKLOG.md`

These items should not interrupt the existing ordered delivery plan.

Recommended insertion points after active contracts stabilize:

1. Fast-complete/drop matrix: during final engine architecture and every protocol integration gate.
2. TLS server-side enrichment: after TLS/public telemetry contracts are stable, before release hardening.
3. Normalized observation metadata audit: during schema-freeze/collector compatibility work.
4. Flow-shape experiment: after state ownership is final and only behind a feature gate.
5. Targeted active-enrichment hook: post-v6 core, optional/default OFF.

## Exit criteria

This enrichment work is successful only if:

- the sniffer remains passive by default;
- disabled features have effectively zero packet-path cost;
- all new per-flow state is strictly bounded;
- no new feature requires cloud connectivity;
- no feature stores packet payloads beyond immediate bounded parsing;
- elephant flows are dropped from inspection as early as possible;
- native Linux and OpenWrt ARM64 performance remains within the project regression budget;
- the collector, not the sensor, owns long-term intelligence and behavioral correlation.
