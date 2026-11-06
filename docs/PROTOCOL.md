# RÚNA Wire Protocol v1

Normative reference for the frame format, handshake, and relay semantics.
Normative reference for implementers. The amendments at the bottom record
additions the original design required implicitly but did not enumerate in
its frame-type table, and the features added since.

## Transport rules

- WSS 1.3 only. Plain `ws://` refused unless `RUNA_ALLOW_INSECURE=1`, which
  also forces a permanent red banner in the UI.
- Binary frames only for document traffic. Control-plane bodies (JOIN,
  JOIN_ACK, PEER_JOIN/LEAVE, PURGE_ACK, ERROR) are UTF-8 JSON. Document
  payloads are ciphertext blobs; shred payloads are canonical CBOR *inside*
  AES-256-GCM.
- Limits: frame ≤ 1 MiB · room log ≤ 32 MiB · peers per room ≤ 32.
  Configurable downward only.

## Frame layout

```
 offset size  field           notes
 ------ ----  --------------  --------------------------------------------
 0      2     magic           0x52 0x55 ("RU")
 2      1     version         0x01
 3      1     frame_type      see table
 4      16    room_id         128-bit internal id
 20     4     epoch           u32 BE, rekey generation (amendment J)
 24     4     nonce_sess      first 4 bytes of this connection's nonce session id
 28     4     flags           bit0 padded, bit1 compressed, rest reserved 0
 --- body: see per-type table
```

The 32-byte header is authenticated as AAD for every encrypted frame, together
with `"runa/v1" || room_id || frame_type || sender_peer_id || counter`.

Encrypted body = `counter` (8 B BE) `||` AES-256-GCM output `||` tag (16 B).

## Frame types

| Value | Name | Dir | Body |
|---|---|---|---|
| 0x01 | JOIN | C→S | JSON `{auth_key_b64? (32 B), session_pubkey_b64 (32 B), client_version, acks?, indexed?, heartbeat?, kx_pubkey?, kx_sig?}`; amendments E, G, H, J |
| 0x02 | JOIN_ACK | S→C | JSON `{peer_id, epoch, log_len, base_index, has_snapshot, ttl, elapsed_secs, ceiling_optout, kdf:{alg,m,t,p,salt_b64}, config_blob?, roster:[{peer_id,pubkey_b64,joined_at_seq,kx_pubkey?,kx_sig?}], acks?, limits?:{max_frame_bytes,frames_per_sec,bytes_per_sec}, indexed?, heartbeat?, log_id, root_epoch}`; amendments E, G, H, I, J |
| 0x03 | DOC_UPDATE | both | encrypted Yjs update, or one part of a split one — amendment E |
| 0x04 | DOC_SYNC_REQ | C→S | JSON `{from_index}` (index form; state vectors leak clocks and are not used) |
| 0x05 | DOC_SYNC_RESP | S→C | one or more encrypted entries: snapshot blob then tail |
| 0x06 | AWARENESS | both | encrypted JSON presence `{h, k, l, c, d?}`: handle, colour index 0–5, cursor line and column, and an optional 16-hex document hash. Receivers ignore `h` and derive the handle from the sender's roster public key, clamp `k`, `l` and `c`, and discard any `d` that is not 16 hex characters. Not the y-protocols awareness format. |
| 0x07 | PEER_JOIN | S→C | JSON `{peer_id, pubkey_b64, joined_at_seq, kx_pubkey?, kx_sig?}`; amendment J |
| 0x08 | PEER_LEAVE | S→C | JSON `{peer_id, reason}` |
| 0x09 | **DOC_ACK** | S→C | JSON `{ok, index?, epoch?}`, to the sender of each DOC_UPDATE, only if its JOIN asked; `epoch` only on a refusal for a stale epoch. Amendments E, J |
| 0x10 | SHRED_REQUEST / SHRED_VOTE / SHRED_CANCEL (0x11, 0x12) | both | encrypted canonical-CBOR payload + Ed25519 signature over CBOR. No count fields exist anywhere. |
| 0x13 | PURGE | S→C | JSON `{reason}` tombstone signal |
| 0x14 | **PURGE_ACK** | C→S | JSON `{request_id}` — amendment A, below |
| 0x15 | **RESTART_NOTICE** | S→C | JSON `{in_secs, handover}`: the process stops in this many seconds; `handover` says whether rooms will carry over — amendments F, I |
| 0x16 | **RESTART_TICKET** | S→C | JSON `{ticket}`, sent as the process stops; the connection is then closed with 1012 — amendment I |
| 0x17 | **PING** | C→S | JSON `{}`, only on a connection whose JOIN asked for `heartbeat` — amendment G |
| 0x18 | **PONG** | S→C | JSON `{roster:[{peer_id,pubkey_b64,joined_at_seq,kx_pubkey?,kx_sig?}]}`; amendments G, J |
| 0x20 | **EPOCH_KEY** | both | signed canonical-CBOR body holding one wrapped secret per recipient. The server reads only the header epoch; amendment J |
| 0x22 | **TTL_EXTEND** | both | JSON `{add_secs}` C→S; server broadcasts `{added_by, add_secs, effective_secs, kind}` — amendment D |
| 0x21 | **SNAPSHOT** | C→S | header ‖ `covers_up_to_index` u64 BE (8 B plaintext) ‖ encrypted blob — amendment B, below |
| 0x30 | ERROR | S→C | JSON `{code}` |

Error codes: 4001 AUTH_FAILED · 4002 RATE_LIMITED · 4003 ROOM_FULL ·
4004 FRAME_TOO_LARGE · 4005 PROTOCOL_ERROR · 4006 EPOCH_STALE ·
4007 TOO_MANY_CONNECTIONS · 4008 SERVER_FULL ·
4010 PURGED · 4011 EXPIRED · 4012 NAME_TAKEN · 4013 NAME_INVALID.

1012 (the standard *Service Restart* close code) ends every connection that
was handed a restart ticket (amendment I).

4007 and 4008 arrive as WebSocket close codes, not ERROR frames: the server
refuses these connections before any frame is read. 4007 means this address
already holds `RUNA_MAX_CONNS_PER_IP` connections; 4008 means the process holds
`RUNA_MAX_CONNECTIONS`. Both are temporary, so clients say so and keep retrying
on their backoff.

**Join failures are deliberately indistinguishable.** A bad key, an unknown
room id, a room mid-purge, and a room that has exhausted its auth attempts all
answer 4001 after the same floor delay. Returning 4002 for the throttled case
made "does this room exist" a five-guess question. Unlisted room ids are
assigned by the server for the same reason: a creation endpoint that answered
409 for a live id and 201 for an unused one is the same oracle by another
route.

Wrong passphrase and missing room are deliberately the same code (4001) with
identical timing (250 ms floor on the auth path).

**JOIN_ACK's expiry fields.** For an absolute expiry, `ttl.secs` is the time
*remaining*, and `elapsed_secs` is the room's age by the server's clock. It is
sent rather than computed by the client, so a difference between the two clocks
cannot look like tampering. `config_blob` is the room's AEAD-protected config,
holding the expiry the creator chose. The client compares `ttl.secs +
elapsed_secs` with that duration and, if the server claims less, shows a
mismatch warning and uses the sealed value. This catches a server that
contradicts itself, not one that lies about both fields; see the threat model's
known limits.

## Server semantics per frame

- The server parses **only** the 32-byte header (plus SNAPSHOT's 8-byte index).
  It never reads past that boundary. Any function that inspects payload bytes is
  a design violation.
- DOC_UPDATE: append to room log (cap enforced), fan out to other peers, and
  acknowledge to the sender if it asked (amendment E).
- DOC_SYNC_REQ `{from_index}`: if `from_index <= base_index` send latest
  snapshot (if any) followed by the full tail; else send tail from
  `from_index`. Responses are re-framed as encrypted blobs relayed verbatim
  from stored log bytes — the server cannot decrypt or merge them.
- SNAPSHOT: record `covers_up_to_index`, drop log entries it supersedes,
  store the opaque snapshot bytes as the room's current snapshot. It verifies
  nothing and understands nothing.
- SHRED_*: relay verbatim to other peers (sender excluded). Count nothing,
  decide nothing.
- EPOCH_KEY: a header epoch one above the room's advances the room to it, and
  only the first such frame for that epoch does; a header epoch equal to the
  room's is a handover and is relayed as it is; anything else is dropped. See
  amendment J for the limits and the overlap window.
- Any encrypted frame whose header epoch is below the room's is refused once
  the overlap window has passed (amendment J).
- PURGE_ACK: mark requester as acked for `{request_id}`; when every currently
  connected socket has acked the same id, execute surtr purge. An ack counts
  only while the peer that sent it is still connected, and the ledger is
  bounded (16 request ids, 128-byte ids, 5-minute expiry) — otherwise a peer
  could bank approvals from throwaway sockets, drop them to shrink the
  denominator, and purge a room the remaining occupants never voted on. There
  is no
  timeout path: an unacknowledged request leaves the room intact.

## Amendments to the master spec's table (documented honestly)

**A · PURGE_ACK (0x14).** Spec §5.6 step 9 has clients acknowledge a shred so
the server can destroy its own copy, but no such frame type exists in §5.2,
and an encrypted ack could not be counted by a blind relay. Added 0x14 as an
unencrypted one-field frame. The server purges only when every peer in the
cohort has acked the same `request_id`, and nothing else can end a room early:
an unacknowledged request leaves it intact. Acks are unauthenticated, which is
acceptable because the quorum — not the individual ack — is the control, and
the server holds no keys either way.

The cohort is fixed when the first ack arrives: every connected peer, except
anyone who joined after the most recent SHRED_REQUEST the server relayed
(within the last hour). The request is never replayed, so a peer who arrives
mid-vote can neither see it nor vote in it — and the voters' clients count
them out too, since the roster is frozen into the request. Counting them here
meant one arrival mid-vote kept a room alive that every voter had shredded.
The snapshot is the server's own, taken as the request passes through, so no
peer can shrink it. A partial set of acks is dropped after 30 seconds: a real
decision's acks all arrive within a round trip, and a stale set would otherwise
hold its cohort over the next one.

**B · SNAPSHOT (0x21) with plaintext index extension.** Late joiners need a
compacted history, which requires the server to truncate at an index it
cannot read from ciphertext, so the index must travel outside it. Added 0x21 whose body begins
with an 8-byte big-endian `covers_up_to_index` before the ciphertext; these 8
bytes are included in the AAD, so tampering breaks authentication and clients
reject the frame. The server learns one integer it already needed; nothing else.

**C · Sender envelope on relayed frames (S→C).** The AAD construction binds
`senderPeerId`, but the 32-byte header has no sender field, and the
receiver needs it to rebuild the AEAD. When the server fans out a C-originated
encrypted frame it emits `original_header(32 B) || sender_peer_id(16 B) ||
original_body`. These 16 bytes are written by the server, never inspected by
it, and are consumed by receivers as an AAD input. Sync responses reuse the
stored entry's original frame type; frame type 0x05 therefore stays reserved.
Server-authored event frames (JOIN_ACK, PEER_JOIN, PEER_LEAVE, PURGE, ERROR,
TTL_EXTEND, DOC_ACK, RESTART_NOTICE, RESTART_TICKET, PONG) are **never enveloped** — receivers read their JSON directly from
the body; only relayed peer ciphertext carries the sender envelope. These
frames also carry epoch 0 by construction, so receivers must exempt them from
the epoch-staleness check. Both invariants are pinned by tests in
`server/tests/hardening.rs`.

**D · TTL_EXTEND (0x22).** Any single peer may extend the room's timer
(shortening still requires shred quorum), but no frame existed for it. Extension pushes the room's effective deadline
out monotonically (never shortens); the server clamps each addition to ≤720 h
**and the accumulated extension to ≤720 h in total**, so replaying the frame
cannot pin a room in memory indefinitely. The broadcast carries both
`effective_secs` (the room's total configured lifetime) and `remaining_secs`
(what is actually left, measured by the server). Clients re-anchor on
`remaining_secs`: `add_secs` is a request, not a result, and a client that
added its own request locally would drift past the real deadline once the
clamp engaged. The clear-text form is acceptable because TTL is public
scheduling information by design — the server must know it to enforce it.

**E · DOC_ACK (0x09), resending, and split updates.** DOC_UPDATE was
fire-and-forget, so a client could not tell an update the server stored from
one written into a connection that had already died — which a browser goes on
reporting as open until TCP gives up, often for minutes. Edits typed in that
window were lost, and nothing noticed.

- A client that sends `acks: true` in JOIN receives one DOC_ACK per DOC_UPDATE
  it sends, in the order sent: `{ok: true, index}` once the frame is in the
  log, `{ok: false}` when the log refused it. Its JOIN_ACK carries `acks: true`
  and `limits: {max_frame_bytes, frames_per_sec, bytes_per_sec}`. A client that
  does not ask sees neither field and never receives 0x09.
- The client keeps each update until it is acknowledged and resends whatever
  is outstanding on its next connection, paced under half of `limits`. An
  update unacknowledged for ten seconds means the connection is dead, and the
  client abandons it without waiting for the browser to agree. Yjs discards
  what it already holds, so resending something that did arrive costs log
  space and nothing else.
- No encrypted frame is sent before JOIN_ACK. Until then the client does not
  know the peer id that receivers bind into the AAD, so anything it sent would
  be rejected by every peer while the server stored it regardless.
- An update that does not fit in `max_frame_bytes` is sent as parts, each its
  own DOC_UPDATE. A part's plaintext is `u32 0xFFFFFFFF` ‖ 8-byte random
  message id ‖ `index` u16 ‖ `total` u16 ‖ data length u32 ‖ data ‖ zero
  padding to a 256-byte bucket. The marker is larger than any real length
  prefix, so a client that predates parts drops one as corrupt rather than
  applying half an update. Receivers apply the update once every part has
  arrived, and do not take a snapshot while any message is incomplete.

The server writes DOC_ACK straight to the sender's socket rather than through
its outbound queue, so a queue full of log replay cannot cost a client its
acks. An ack is not authenticated: a hostile server can acknowledge an update
and then discard it. That is no new power — it holds the log and can drop
anything — and it is the same exposure every relayed frame already has.

**F · RESTART_NOTICE (0x15).** Rooms live only in memory, so stopping the
process ends every room, and a redeploy used to do that mid-session with no
warning. On SIGTERM, with anyone connected, the server sends `{in_secs}` to
every open room and waits that long (`RUNA_SHUTDOWN_GRACE_SECS`, default 60)
before stopping, so people can export. A peer that joins during the countdown
receives the notice straight after JOIN_ACK, with the seconds left. Room
creation answers 503 `{"code":"RESTARTING"}` until the process stops. The wait
ends early if everyone disconnects, and a second signal ends it at once. With
nobody connected the server stops immediately. The notice is server-authored
and unauthenticated, like every server event: a hostile server could announce a
restart that never comes, but it could end a room at any moment regardless.

**G · PING (0x17) and PONG (0x18).** Acks (amendment E) cover a connection
something is being sent on. One that died while nobody typed sent nothing that
could go unacknowledged, so it was noticed at the next keystroke — and until
then the page showed the room as connected while everyone else's edits went
nowhere.

- A client that sends `heartbeat: true` in JOIN has it echoed in JOIN_ACK, and
  may then send PING. The server answers each with PONG, written straight to
  the socket like DOC_ACK. A client pings every 15 seconds and abandons a
  connection whose PONG is 10 seconds late.
- PONG carries the room's current roster. JOIN_ACK was the only full roster a
  client ever received, so a client that missed a PEER_JOIN or PEER_LEAVE kept
  the wrong one until it reconnected. The roster is read in the same task that
  writes the PONG, so no older view of it can arrive after a newer one; the
  client applies the difference through the same handlers as the events it
  missed. Like every roster, it is a server claim and is treated as a hint.
- PING on a connection that did not ask is still a protocol error.

**H · Log indexes on relayed updates.** A snapshot tells the server which log
index it covers, and the server discards everything below it. The client could
only estimate that index from its own stored updates, which undercounts by
every update anyone else wrote — and once a member with fewer of its own became
the snapshotter, its estimate fell below the previous snapshot and the server
refused it, since a snapshot may never move backwards. Compaction then stopped
for the life of the room, and a long session filled its log until edits were
refused.

- A client that sends `indexed: true` in JOIN has it echoed in JOIN_ACK, and
  every DOC_UPDATE relayed to it, live or replayed, arrives as
  `header(32) ‖ sender(16) ‖ index(u64 BE) ‖ body`. Other frame types, and
  connections that did not ask, keep the plain envelope.
- The client counts an entry once its content is in the document: applied,
  its own and acknowledged (DOC_ACK already carries the index), or covered by
  a snapshot it applied. An entry nobody can decrypt counts as well, since
  nothing will ever read it. A part of a split update counts only when the
  whole update has been applied, so an incomplete one holds back every
  snapshot after its first part. The snapshot index is the length of the
  unbroken run from zero, and sync requests resume from it.
- The index is written by the server and is outside the AEAD. A server that
  lied about it could make a snapshot cover entries the client never saw, and
  those would be lost — no new power, since it holds the log and can drop any
  entry anyway.

**I · RESTART_TICKET (0x16), log ids, and rooms that outlive a restart.**
Amendment F gave people a minute's warning before a restart ended their room.
But the people in a room still hold everything that matters — the document
and the key — so the room need not end at all. What stopped it coming back was
the new process: it had never heard of the room, and a client that could
declare one into existence could squat any id or name, or bring back a room its
members had shredded.

- With `RUNA_RESTART_KEY` set (64 hex characters, the same for the stopping
  and the starting process), RESTART_NOTICE says `handover: true`. When the
  countdown ends, every member of every active room is sent RESTART_TICKET and
  its connection is closed with 1012. The ticket is the old process vouching
  for the room at the moment it stopped: HMAC-SHA-256 under the key, over its
  id, name, creation time, TTL and extension, KDF parameters and salt,
  verifier and config blob, with an expiry ten minutes on.
- Issued at the very end, not with the warning, so a room shredded during the
  countdown leaves nobody holding a way back. Nothing is written to disk: the
  key is configuration, and the tickets live in members' tabs.
- A member whose JOIN is refused with 4001 while holding a ticket presents it
  to `POST /api/rooms/restore {ticket}`. 201 means restored and 200 means
  another member got there first; either way it joins again. 400 or 410 mean
  the room is not coming back (a bad or expired ticket, a room shredded or
  expired in the new process, an absolute TTL that ran out during the
  restart, or no key); 409 means its name was taken in between; 429 and 503
  are retried for up to nine minutes. The ticket's contents must pass exactly
  the validation a new room's would, under the new process's configuration.
- JOIN_ACK carries `log_id`, random per room instance. A restored room keeps
  its id and has a new, empty log, so a member that sees `log_id` change
  replaces everything it had queued with its whole document and resyncs from
  zero. Yjs merges every member's copy and drops what repeats. A member that
  was offline at the restart and has no ticket catches up the same way once
  anyone has restored the room.
- Only members connected when the process stopped are handed tickets. A room
  with nobody in it at that moment still ends, as before.
- Tickets are bearer tokens for recreating a room, not for entering one: the
  restored room holds the old verifier, so joining still takes the key.

**J · Epochs, EPOCH_KEY (0x20) and key agreement.** The epoch field and the
EPOCH_KEY frame type were in the first version of this protocol with nothing
behind them. This amendment gives them meaning. What rotation claims is in the
threat model's section on key rotation.

*Key schedule.* A room's root is what it has always been: the link and
passphrase material, from which `auth`, `content` and `fp` are derived. Epoch
0 uses that `content` key, so a room that never rotates is unchanged. Next to it
every member derives `chain_0 = HKDF(ikm, room_salt, "runa/v1/chain")`. To move
from epoch n to n+1, a member draws a 32-byte random `epoch_secret` and every
member computes, with `chain_n` as the HKDF key and the secret as the salt:

```
content_{n+1} = HKDF(chain_n, salt = epoch_secret, info = "runa/v1/epoch/content")   AES-256-GCM
chain_{n+1}   = HKDF(chain_n, salt = epoch_secret, info = "runa/v1/epoch/chain")
confirm_{n+1} = HKDF(chain_{n+1}, info = "runa/v1/epoch/confirm")                      16 bytes
```

Each frame is encrypted under the content key of the epoch in its header. A
sender's nonce session and counter prefix are drawn fresh for every new key.
A replayed log legitimately spans several epochs, so a client reads stored
entries (DOC_UPDATE, SNAPSHOT) under whichever epoch's key it holds. It drops
live-only frames (AWARENESS and the SHRED frames) from before the overlap
window with the stale-epoch warning, and drops frames from an epoch it does not
hold yet without counting them, since it will read them from the log once it
has the key.

*Key agreement.* JOIN carries `kx_pubkey`, an ECDH P-256 public key made for
this session (65-byte uncompressed point, base64), and `kx_sig`, the session's
signature over `"runa/v1/kx" || room_id || kx_pubkey`. Every peer uses P-256
for this, whatever its signing algorithm, because two peers on different
curves could not agree a key. The server checks only their lengths and that
the key starts with 0x04, and relays both in JOIN_ACK's roster, PEER_JOIN and
PONG. A receiver verifies `kx_sig` against the roster's signing key for that
peer and treats a peer whose signature fails as one it cannot send keys to.

A client that predates this amendment sends neither field and can never be
handed a key. Restart tickets keep such tabs open across a deploy, so the
server keeps them out of any room whose key has changed: a JOIN without
`kx_pubkey` into a room whose epoch differs from its root epoch is refused
with ERROR 4005, and when a room's epoch advances, every connection in it that
joined without `kx_pubkey` is sent ERROR 4005 and closed with code 4005. Left
in, such a client would lose its edits without saying so, and after a
reconnect it would label frames with the room's epoch while encrypting them
under the root key, which the person who left still holds. A room that has
never rotated admits it as before.

The key that wraps a secret for one recipient is
`HKDF(ECDH(own kx, their kx), salt = room_id || epoch (u32 BE), info = "runa/v1/epoch-wrap" || sender_peer_id || recipient_peer_id)`,
used with AES-256-GCM, a random 12-byte IV, and the frame's 32-byte header as
AAD.

*EPOCH_KEY body.* It is not encrypted under the content key, since a newcomer
does not have the current one. It is `len (u32 BE) || cbor || sig`, where `cbor`
is a canonical CBOR map:

```
{ "kind":    "step" | "handover",
  "from":    u32,          the epoch the sender was in
  "to":      u32,          equal to the header epoch
  "root":    u32,          the epoch of the room's current root
  "sender":  bstr(16),     must equal the relay envelope's sender
  "roster":  bstr(32),     the sender's roster hash, as for shred votes
  "confirm": bstr(16),     confirm_to; one value for every recipient
  "wraps":   [ { "p": bstr(16) peer id, "iv": bstr(12), "ct": bstr } ] }
```

and `sig` is the sender's signature over `"runa/v1/epoch-key" || header (32 B) || cbor`.
A step's wrap holds the new `epoch_secret`. A handover's wrap holds the secrets
from `root + 1` to `to`, concatenated in order, so the newcomer derives every
epoch from its own link or passphrase. A handover is addressed to one
newcomer and carries exactly one wrap, of at most 8192 secrets; a room that has
rotated more often than that since its root can no longer be joined, which at
one rotation per 5 seconds takes over eleven hours of continuous departures.
A receiver checks the signature against its roster, unwraps its own entry,
derives, and compares `confirm`. A frame
that fails any of these is refused, and the refusal is shown. It also compares
the roster hash with its own: a mismatch is shown as a warning that someone may
be hidden from the room, but does not stop the step, because two honest peers
can briefly disagree about a departure that is still in flight.

*When a room rotates.* In a Highest-security room, a peer that has been gone
for 60 seconds starts a step, as does any peer gone ten minutes after a restart
notice that promised a handover. A peer that comes back with the same signing
key in that time does not, and several departures inside one window make one
step. The step is sent by the remaining peer with the lowest `joined_at_seq`;
if none has arrived 15 seconds after the deadline, the next one in that order
sends it. Everyday rooms do not start steps, though their clients accept one.
After a step, the peer the server lets snapshot (the lowest `joined_at_seq`)
sends a snapshot under the new key as soon as it can, and keeps trying on its
regular snapshot timer until one has been sent at the new epoch. In a quiet
room that can wait for the next edit, so "soon" means once anything new is
written.

A client whose JOIN_ACK has no `root_epoch` is talking to a server that
predates this amendment, which neither moves the epoch nor echoes steps. It
sends no steps and ignores any it receives.

*Newcomers.* JOIN_ACK carries `root_epoch`. A newcomer whose JOIN_ACK says
`epoch == root_epoch` derives its keys as it always has. Otherwise the member
with the lowest `joined_at_seq` sends it a handover when it sees the PEER_JOIN,
and the next member in that order does so if none has arrived after 10 seconds.
A member that reconnects cannot rely on having seen every PEER_JOIN, so it
schedules a handover for every member its JOIN_ACK lists whose signing key it
has not seen before. A second handover is harmless: a member that already
holds the epoch ignores it.

A handover's `confirm` is chosen by its sender, so a member who holds the link
could hand a newcomer secrets that match a confirm it made up. Any other member
who sees a handover for someone else whose `confirm` differs from its own for
that epoch shows the handover as refused, and still sends its own if it was
going to.

*Server rules.*

- An EPOCH_KEY whose header epoch is one above the room's advances the room,
  atomically, so the first such frame wins. A later step for the same epoch
  then matches the room's epoch and is relayed like a handover, and every
  client ignores it, because a step must name the epoch after the one the
  client holds. A client that the winning step left out is waiting for a
  handover, and ignores every step for the epoch it is waiting for or an
  earlier one, so a losing step that happens to include it cannot put it on
  a key nobody else holds. Advances are refused for 5 seconds after the last
  one and at `u32::MAX`. An accepted step is relayed to every peer *including its sender*,
  and every peer, the sender too, moves to the new epoch when that copy
  arrives, so the server's order is the only order. A refused step is dropped
  without an answer; its sender applies whichever step does arrive. A header
  epoch equal to the room's is a handover and is relayed to the other peers.
  Anything else is dropped.
- For 30 seconds after an advance, encrypted frames from the previous epoch
  are still accepted, so edits already in flight land. After that, an
  encrypted frame (DOC_UPDATE, SNAPSHOT, AWARENESS, the SHRED frames) from an
  earlier epoch is refused, and so is one from a later epoch than the room's: a
  DOC_UPDATE is not stored, and a sender that asked for acks gets
  `{ok: false, epoch}`; any other frame is dropped, and its sender gets ERROR
  4006. A client refused this way reconnects, which resends everything not yet
  stored, and waits for a handover if it does not hold the room's current key.
  An honest client is refused only when it is more than 30 seconds behind, and
  then it has no newer key to resend with. A SNAPSHOT is stored only at the
  room's epoch: one from the epoch just left, inside the overlap, is dropped
  without an answer, because the member that steps is usually the one that
  snapshots; one from any other epoch gets ERROR 4006.
- PING, TTL_EXTEND, PURGE_ACK and DOC_SYNC_REQ carry no ciphertext and are
  never refused for their epoch. Server-authored frames still carry epoch 0.
- Restart tickets cover `epoch` and `root_epoch`. A ticket from a process that
  predates this amendment has neither, and restores the room at 0.

Every rotation is visible to the server: it relays the frame and moves the
epoch. It already saw the departure that caused it. The secret itself reaches
only the peers it was wrapped for.

All amendments keep the invariant that matters: the server never learns
anything about document content.
