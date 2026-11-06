# RÚNA Threat Model

This document defines exactly what RÚNA claims to defend against. Any
security claim elsewhere in the product or its marketing must be consistent
with it. Where a claim conflicts with this document, this document wins.

## Assets, ranked

1. **Document plaintext.** The only thing that truly matters.
2. **Content encryption key material.** Compromise equals asset 1.
3. **Room passphrase.** Reused passwords make this worse than it looks.
4. **Participation metadata.** Who connected, when, from where, for how long.
5. **Document existence and shape.** Length, edit cadence, peer count.

## Adversaries

| ID | Adversary | Capability assumed | In scope |
|---|---|---|---|
| A1 | Passive network observer | Reads all traffic, cannot break TLS | Yes |
| A2 | Honest-but-curious server operator | Full server RAM, disk, logs, process memory | Yes |
| A3 | Malicious server operator | A2 plus can modify relayed messages, forge peers, drop votes, and serve modified JS | Partially. See the honest limits below. |
| A4 | Hostile peer in the room | Has the key and the plaintext, wants to break others or persist the doc | Partially. See the honest limits below. |
| A5 | Off-path attacker with the room URL but not the passphrase | Online guessing only | Yes |
| A6 | Attacker with post-hoc access to the server host | Cold RAM, swap, core dumps, disk | Yes, best effort. See "Known limits" below. |
| A7 | Attacker with access to a peer's endpoint | Malware, screen capture, keylogger | **No.** Out of scope. |
| A8 | Global adversary doing traffic correlation | Timing and volume analysis across the network | **No.** Use Tor, and the server's onion address where it has one. |

## What RÚNA actually defends against

- **A1:** TLS plus a second, independent layer of AES-256-GCM. Even a full TLS
  compromise yields ciphertext.
- **A2:** The server holds ciphertext, a 32-byte auth verifier, and connection
  state. There is no key material to steal, because none is ever sent.
- **A5:** Argon2id at 64 MiB makes offline attack expensive, and there is no
  offline attack surface anyway because the verifier is a SHA-256 of a 256-bit
  random-equivalent value. Online guessing is rate-limited and locked out.
- **A6:** No disk persistence, `mlock` on secret buffers, core dumps disabled,
  `panic = "abort"`, and explicit zeroization on drop.

## The honest limit: a malicious server can serve you bad JavaScript

This is the unfixable weakness of every browser-delivered E2EE application,
including Signal's web clients, CryptPad, and every "encrypted pastebin" ever
shipped. If the server decides to serve a targeted user a modified bundle that
exfiltrates the key, the user's browser will run it, and no amount of clever
protocol design inside that bundle helps.

What can be done, and what RÚNA does:

- Zero third-party script origins. No CDN, no analytics, no hosted fonts.
- Strict CSP with `script-src 'self' 'wasm-unsafe-eval'` — scripts only from
  this origin, WebAssembly allowed to compile because Argon2id needs it, `eval`
  still forbidden — and Subresource Integrity on every asset.
- Trusted Types enforced, with the policy allow-list naming only `default` and
  the nine policies monaco-editor creates. **Honest limit:** the `default`
  policy's `createHTML` is a pass-through compatibility shim for Monaco's own
  DOM writes — it is not a sanitiser. The control that protects document
  content is `rehype-sanitize` in `web/src/render/pipeline.ts`. What the
  `default` policy does enforce is `createScriptURL`, which is restricted to
  same-origin URLs.
- Reproducible builds, with the SHA-256 of the release bundle published in the
  git tag and served at `/version`.
- Release binaries, their SBOMs and the container image signed with `cosign`,
  keyless.
- Every third-party GitHub Action pinned to a full commit SHA, so moving a
  tag upstream cannot change what runs in the release job that holds the
  signing identity and the GHCR push token.
- A self-host path that is one `docker run`, documented as the answer for
  anyone whose threat model includes the operator.

What must **not** be done: claim this problem is solved.

## The honest limit: nonce separation rests on 64 bits

Every peer in a room encrypts under the same AES-256-GCM key. The only thing
keeping two of them off the same nonce is the 12-byte `sess || counter`, of
which 8 bytes are random per session (a 4-byte session id and a 4-byte counter
prefix). Nonce reuse in GCM is not a degradation but a total break: the XOR of
the two plaintexts falls out and the authentication key leaks.

64 bits puts the birthday bound past 2^32 sessions, which is far beyond any
room's lifetime. It is not, however, the 96 bits a random-nonce scheme would
give, and it is worth knowing which number the guarantee rests on. Widening the
session id is a wire-format change and is deferred to a protocol revision.

The counter never restarts within a session — a client that rebuilt its cipher
mid-connection would replay nonces, which is why JOIN_ACK re-labels the sender
in place and is accepted only once per connection.

## The honest limit: consensus shred is not a confidentiality control

Any peer who can read the document already has the plaintext in their browser.
They can copy it, screenshot it, or leave a tab open. Shred removes the shared
live copy and destroys the keys. It does not and cannot reach into another
person's machine.

What consensus shred is actually good for:

- Preventing accidental or unilateral destruction of shared work.
- Making the server's copy provably unrecoverable, since it never had keys.
- Giving a group a clear, agreed, observable moment of "this is over."

The UI says this in plain words at the moment of first use, once — not in a
terms page nobody reads.

### And consensus is a guarantee against your peers, not against the server

Worth stating outright, because the premises are elsewhere in this document and
the conclusion was not.

A shred vote is a signed object, and each receiver checks the signature against
the public key its roster holds for the claimed signer. That roster comes from
the server — `JOIN_ACK` on joining, `PEER_JOIN` afterwards. A3 already says a
malicious operator can "forge peers"; this is what that costs. Substitute your
own key for every peer, sign a request and a vote from each, and you have a
unanimous decision nobody took, which destroys the shared copy and runs the
wipe in every connected browser.

It grants a hostile operator no capability they lacked. They hold the log and
can drop it; they can disconnect everyone; they can refuse to relay. Destroying
a room is something they could already do more simply. And confidentiality is
untouched either way — the server never holds a key, so forging a vote reveals
nothing.

What it means is narrower and worth being precise about. "Everyone must agree"
is enforced by cryptography against your fellow occupants: a peer in the room
cannot shred alone, cannot forge your approval, and cannot claim a threshold
lower than your own roster supports. Against whoever runs the server it is
enforced by nothing, because they are the one telling you who the peers are.

If that distinction matters for your use, the mitigation is the same as for
every other A3 risk: run the server yourself. Nothing in the protocol can fix
it, because a peer's identity has to arrive from somewhere, and on a first
visit that somewhere is the relay.

## Key rotation protects against people who have left, within limits

A room starts with one content key, derived from its link or passphrase. In a
Highest-security room the key changes when someone leaves. Once a peer has been
gone for 60 seconds (ten minutes during a server restart, so everyone has time
to reconnect), the remaining peer who has been connected longest draws a new
256-bit secret. It wraps that secret separately for each remaining peer, under
a key agreed with that peer's session key, and sends it. Everything written
after that is encrypted under a key the departed peer never receives, apart
from what a member who has not yet received the new key sends in the 30
seconds the server still accepts the old one. The design is in PROTOCOL
amendment J.

What that buys is narrow, so here it is exactly:

- **It stops someone who left from reading on quietly.** Without rotation, a
  departed peer who kept the key could read everything written afterwards from
  ciphertext alone, if a colluding operator or a captured stream gave it to
  them. With rotation, that ciphertext is useless to them.
- **It does not stop them coming back.** They still hold the link or the
  passphrase, so they can rejoin, appear in the peer list like anyone else, and
  be handed the current key. Rotation turns silent reading into a visible
  return.
- **It gives no backward secrecy.** A departed peer keeps everything they saw
  while they were there.
- **Everyday rooms do not rotate when someone leaves.** An everyday room
  promises that its link opens it later, and a rotated room cannot keep that
  promise: what was written after a rotation can be opened only through someone
  who is still in the room. A Highest room accepts that cost. If everyone leaves
  after a rotation, the link no longer opens what was written since, and the
  room tells the next person who arrives. A server that strips an everyday
  room's sealed configuration makes it behave as Highest, so it rotates; that
  costs availability, not confidentiality, and the server could delete the room
  anyway.
- **A tab opened before key rotation existed is kept out once the key has
  changed.** It cannot be handed a new key, so the server refuses it with a
  version error and it has to be reloaded. Left in, it would lose its edits
  without saying so, or write them under the original key.

A peer who joins after a rotation still gets the whole history. A member who is
present hands them the secrets drawn since the room began, and they derive each
key from their own link or passphrase. Until that happens, the room shows them
that it is waiting for a member.

Every rotation is signed, and it carries a confirmation value that each
recipient recomputes from the key it derived. A peer who hands different
members different secrets fails that check. Someone without the link cannot
hand a newcomer false secrets either, because they cannot compute the
confirmation. A member who holds the link can: the newcomer would then hold
keys nobody else has, and nothing would open. Other members who see that
handover notice that its confirmation does not match their own, say so, and
send their own. A rotation that fails is refused and shown, and the room stops
working until people leave it. Only a member or the server can cause that, and
either could already disrupt a room.

Against the server, rotation holds as long as the server does not collude with
the departed peer. Each new key comes from the secret mixed into a chain that
starts at the link or passphrase, which the server never sees, so intercepting
a wrapped secret gives the server nothing on its own. But the session keys that
secrets are wrapped to arrive in the peer list, and the server supplies that
list. A server working with a departed peer can put its own key in place of a
member's and pass the new secret on. The two-word handles in the room are
derived from session keys, but they are short enough for a server to find a key
that produces the same handle, so comparing them does not catch this. A
server can also hold a rotation back by never relaying it: the member rotating
keeps trying, and nothing tells anyone that the change is overdue. As
everywhere in this document, nothing here helps against a server that serves
bad JavaScript, and running the server yourself is the answer to both.

## Metadata the server unavoidably learns

| Leak | Why | Mitigation |
|---|---|---|
| Your IP address | It is a TCP connection | Never logged. Rate limits hold only a keyed pseudonym (HMAC under a key drawn at startup and never written), dropped about one limiter window after you go quiet; a restart makes every earlier pseudonym unlinkable. Whoever captures the live process holds the key too and can test a suspected address, so this bounds exposure in time rather than removing it. Over Tor the server never learns an address at all; through an onion service each circuit is limited on its own, and no forwarded-for header is believed there |
| That a room exists and when | Routing | Unlisted room IDs are 128-bit and unguessable; identical responses for "wrong password" and "no such room". Named rooms give this up by construction. |
| Number of connected peers | Relay fan-out | Not hideable in a client-server relay |
| Approximate document size | Ciphertext length | Padding to 256-byte buckets |
| Edit cadence and typing rhythm | Frame timing | Update coalescing on an 80 ms timer; optional constant-rate mode closes the channel entirely at a bandwidth cost |
| Session duration | Connection lifetime | None |
| Room TTL | The server enforces it, so it must know it | None. It is a scheduling parameter, not a secret |
| A named room's name | It is the routing address | None, by construction. This is the entire trade; it is why named rooms are a separate class with a separate promise |
| When a room's key changes, and how many times | It relays each rotation and enforces the room's current epoch | None. It already sees every departure that causes one |

## Known limits stated plainly

`Vec`/`String` growth reallocates and leaves stale copies behind; the allocator
may not return pages promptly; a root-level attacker on the host reads process
memory regardless; JavaScript strings are immutable and cannot be individually
zeroized, which is why client wipe ends in realm destruction via hard
navigation. `zeroize` narrows a window; it does not close a door.

The unlisted room key travels in the URL fragment. A fragment is never sent
to the server, but browsers write the full URL into their history, and a
browser with sync on copies that history to its vendor. So the client keeps
the key out of the address bar (`web/src/keyhandoff.ts`):

- A room opened from inside RÚNA — created on the front page, or joined by
  pasting its link into Join — gets the key handed over in memory. It is
  never in the address, so no history entry can carry it.
- A room opened from a clicked link has the fragment removed by
  `history.replaceState` as the page starts. The browser may already have
  recorded the address it was opened with, and no page can reach that entry.
  Measured in headless Chromium: after opening a room this way, no file in
  the profile held the key. Headless Chromium keeps no history database,
  though, so that run cannot speak for a desktop browser's history.
- After joining, an *everyday* room keeps the key in the tab's
  `history.state` so a refresh works. That is not the address, is not shown
  in or synced with history, and goes with the tab; a browser's session
  restore may keep it on disk until then. A *highest-security* room keeps it
  in memory only, and a refresh forgets it.

A shared room has no key in its address, but its address *is* its name, and
the name in someone's history says which room they were in. Opened from
inside RÚNA, a shared room sits at `/` with the name in memory, and takes
`/<name>` only once its sealed config says *everyday*; a *highest* one keeps
`/`, so a refresh leaves it. A name typed or clicked into the address bar is
taken out as soon as the room says *highest*, with the same caveat as a
clicked link. Its passphrase was never stored; a highest room's create form
also sets `autocomplete="off"`, which browsers may still override with an
offer to save, so the room tells people to decline it.

The level is chosen at creation and sealed in the room's encrypted config,
so the server cannot see it. A config that is missing or will not open is
treated as highest: a server that strips it cannot have a highest-security
room's key saved in the tab.

Someone who later reads a participant's history or sync account can open any
room whose clicked link was recorded there and is still alive. The README's
"If your safety depends on it" says to paste links into Join, and to make
rooms for people at risk with Highest security.

Delivery acknowledgements come from the server and are not authenticated. A
client stops resending an edit once the server says it stored it, so a hostile
server can confirm an edit and then throw it away. That is the same power as
dropping it, which a server holding the only copy of the log always had; the
acknowledgement is there to survive a dead connection, not a dishonest relay.

The expiry warning catches a server that contradicts itself, not one that lies
consistently. For a room with an absolute expiry, JOIN_ACK reports the time
remaining and `elapsed_secs`, the room's age by the server's clock. The client
adds the two and compares the sum with the duration sealed in the room's
encrypted config, and warns, and keeps the sealed value, if the server claims
less. A server that also inflates `elapsed_secs` makes the sum come out right
while ending the room early, and no warning appears. A server that omits
`elapsed_secs` skips that comparison, though the check that the kind of expiry
matches still runs. Neither gains the server anything, since it can delete a
room whenever it likes. What the check does is stop a server from shortening a
room by changing one number, and make a bug that does so visible.

The restart warning is server-authored and unauthenticated, like every other
server event. A hostile server can announce a restart that never comes, or stop
without announcing one. It could end a room at any moment regardless. The
warning exists so that an honest operator's redeploys stop costing people their
documents.

Restart tickets (PROTOCOL amendment I) let a room outlive a restart without the
server writing anything down. What makes that safe is what a ticket cannot do:

- **It cannot open a room.** It recreates one with the verifier it had, so
  joining still takes the key. A leaked ticket lets its holder recreate an
  empty room nobody can enter without the key — and only for ten minutes.
- **It cannot undo a shred.** Tickets are issued when the process stops, only
  for rooms still alive at that moment, so a room shredded before then has
  none. One shredded after it was brought back is a tombstone in the new
  process, which refuses the ticket.
- **It cannot be minted without the key.** `RUNA_RESTART_KEY` is operator
  configuration, kept out of the world-readable env file. Someone who has it
  can recreate rooms of their choosing under chosen ids and names, but every
  field still passes the same validation as a new room, and the verifier still
  guards entry. They could squat a name, which anyone can already do while it
  is free.

Requests from pages on other sites are refused at `/api` and `/socket`, by
`Origin` (sent on every WebSocket handshake and POST) and `Sec-Fetch-Site`.
Nothing rides on cookies, so another site could never read anything; what it
could do was make its visitors' browsers send bad joins, spending those
visitors' own per-address guess budget until their real rooms were refused
with the same answer as a missing room. Clients that are not browsers send
neither header and pass, since they cannot act through someone else's browser.

Log indexes on relayed updates (amendment H) are written by the server outside
the AEAD. A server that lied about them could have a snapshot cover entries the
client never received, and those would be lost to later joiners. That is the
same power as dropping the entries, which the server holding the log always
had.
