# Changelog

Newest first. The release workflow reads the section matching the tag and
publishes it as the release notes, and refuses to build a tag that has no
section — so this file is not documentation of the release, it is part of it.

## Unreleased

### Added

- **Highest-security rooms change their key when someone leaves.** Once a
  person has been gone for a minute (ten minutes during a server restart, so
  everyone can reconnect), the person who has been in the room longest draws a
  new secret and hands it to each remaining member under a key agreed with that
  member alone. What is written afterwards is under a key the person who left
  never receives, so they can no longer read along quietly from ciphertext. They
  can still come back with the link, visibly, like anyone else. Someone who joins
  later is handed the secrets by a member who is present and reads the whole
  history. Everyday rooms keep their promise that the link opens them later, so
  they do not rotate on a departure. The design and its limits are in
  `docs/THREAT_MODEL.md` and `docs/PROTOCOL.md` amendment J. A tab still
  running an earlier version can't be handed the new key, so once a room's key
  has changed the server turns it away. The older page doesn't say why; it keeps
  trying to connect until it is reloaded. Removing someone and changing a
  room's link come in a later release.

### Fixed

- **The deploy never actually let unattended-upgrades patch Caddy.** 0.5.4
  checked where Caddy comes from with `apt-cache policy caddy | grep -q`, and
  the deploy runs under `pipefail`. `grep -q` stops at the first match,
  `apt-cache` then dies of SIGPIPE on its long output, and the check read as
  false, so `/etc/apt/apt.conf.d/52runa-caddy` was never written. The check
  now captures the output and matches it without a pipe. The same shape was
  removed from the running-config check and the Tor key check, where it had
  not caused a failure.

## 0.5.4

### Security

- **The onion service runs a maintained Tor.** `RUNA_ONION=1` installed tor
  from Ubuntu, which keeps it in universe without routine security updates:
  24.04 still had 0.4.9.11, which a remote peer can crash (CVE-2026-87724) and
  which lacks the high-severity onion-service fixes of 0.4.9.14. The deploy now
  takes tor from the Tor Project's repository, trusting its signing key only
  after checking the published fingerprint, and lets unattended-upgrades keep
  it current. Run the deploy again with `RUNA_ONION=1` to move an existing box.
- **Caddy keeps itself patched.** Caddy's official apt repository is outside
  unattended-upgrades' default list, so the hosted box stayed on 2.11.7 while
  2.11.8 and 2.11.9 carried security fixes. Where Caddy comes from that
  repository, the deploy now adds it to unattended-upgrades.
- **Five vulnerabilities fixed in 0.5.0 are now published as advisories.**
  They affected 0.2.0-rc.3 through 0.4.0: a cross-site lockout (Medium), a
  room-wide join lockout, a shredded room that could stay open, a shred vote
  any member could cancel, and passphrase rooms that silently used PBKDF2 in
  place of Argon2id (all Low). `docs/SECURITY.md` lists each one with its
  severity; anyone still running 0.4.0 or earlier should upgrade.

## 0.5.3

### Changed

- **RÚNA now lives at [github.com/vardrlabs/Runa](https://github.com/vardrlabs/Runa).**
  The repository moved from `icrkdev/Runa` to the Vardr Labs organisation, and
  old links and clones redirect. Two things move with it and matter for
  verification. Images from this release on are published at
  `ghcr.io/vardrlabs/runa`; earlier ones stay at `ghcr.io/icrkdev/runa`, whose
  `latest` stops at 0.5.2. Releases from this one on are signed as
  `vardrlabs/Runa`, so `docs/SECURITY.md` now gives the identity for each.

## 0.5.2

### Security

- **A release can no longer go out unsigned without failing.** The signing
  steps now check that every binary and bill of materials has its `.sig` and
  `.pem` beside it, instead of trusting cosign's exit status. The first
  automated update of the pinned actions would have moved cosign from 2.5.2
  to 3.0.6, which ignores the flags those files come from and still exits
  successfully, so the next release would have shipped nothing to verify.
  cosign stays on 2.5.2, named explicitly, until the move to its bundle
  format is made on purpose together with `docs/SECURITY.md`.
- **The fuzz job asks for nightly by name.** The same update pinned it to the
  commit of the toolchain action's `stable` branch, which differs from
  `nightly` only in its default, so fuzzing would have run on stable and
  failed. Every toolchain step now says which toolchain it wants.
- **Actions moved to their current releases:** checkout 7, setup-node 7,
  upload-artifact 7, download-artifact 8, the Docker build actions, and
  action-gh-release 3, still pinned to commit SHAs. download-artifact now
  fails the release on a digest mismatch rather than warning.

### Fixed

- **WebKit on Linux could hang a room on CONNECTING.** GNOME Web, WPE and
  Playwright's WebKit build Ed25519 keys on libgcrypt, which drops leading
  zero bytes, so about one key generation in 128 fails with OperationError.
  The client tried Ed25519 once as a probe and then again for real, and when
  the second attempt failed the room never opened. It now uses whichever key
  it managed to make, and falls back to ECDSA P-256 for that session if
  Ed25519 fails. Safari on macOS and iOS uses a different crypto library and
  was not affected. This was the intermittent WebKit failure in CI.

## 0.5.1

### Security

- **tokio 1.54.1, clear of two advisories published in October 2026.**
  RUSTSEC-2026-0386 lets tokio's `AsyncFd` constructors leave the I/O driver
  pointing at freed memory. RÚNA never creates an `AsyncFd`, and nothing it
  depends on does either, so no released build could reach it. It is cleared
  anyway, because the advisory check fails on it, and a check that fails for
  a reason that does not apply is a check people learn to ignore. The bump
  goes past 1.54.0 on purpose: that release has a use-after-free in
  `tokio::time::Interval` (RUSTSEC-2026-0384), and the server ticks an
  `Interval` for its room scheduler and for forgetting rate-limit entries.
  1.54.1 fixes it, and 1.54.0 has been withdrawn from crates.io.
- **vitest 4.1.12** (GHSA-qxg6-89mg-rqv8). Development only: the flaw needs
  vitest's mocker plugin on a dev server someone else can reach, and RÚNA's
  tests use neither. The shipped web bundle is byte for byte the same.
- **CI and release actions pinned to commit SHAs.** Every third-party action
  in the CI, release and fuzz workflows now names a full commit SHA, with its
  release tag in a comment, and Dependabot proposes the updates weekly. The
  release job holds the keyless signing identity and the GHCR push token, so
  an action whose tag was moved upstream could otherwise have signed or pushed
  an image of its own. Nothing suggests that happened; this closes the door.

### Fixed

- **`docs/PROTOCOL.md` described presence wrongly.** It said message `0x06`
  carries a y-protocols awareness update. It never has: presence has been an
  encrypted JSON frame of RÚNA's own since 0.1.0, and the receiver derives the
  sender's name from the roster rather than trusting the frame. The table now
  gives the real fields and how each is checked, so a compatible client can be
  written from the spec.

### Removed

- **`y-protocols`**, a dependency nothing imported. It is gone from the web
  client, `NOTICE` and `docs/ATTRIBUTION.md`. The bundle is unchanged, since
  nothing in it came from that package.

## 0.5.0

### Security

- **Join will not open a disguised or unencrypted link.** A link such as
  `https://runa.vardrlabs.com@elsewhere.example/…` leads to the host after the
  `@`, so Join now refuses any link with an `@` in its address and says where
  it really goes. A room on another server reached over plain http would hand
  its key to a page anyone on the network could rewrite, so Join opens http
  links only to an onion address or to this machine, and reads a link pasted
  without its scheme as https. Join and Create also check every address
  once more just before the page moves: a path on this server, or a room
  elsewhere that passes the same rules, and never `javascript:` or `data:`.
- **A room's key no longer sits in the address bar, or in browser history.**
  The key is the part of the link after `#`. It never reached the server, but
  it stayed in the address bar for as long as the room was open, and browsers
  write the full address into their history — which, with sync on, leaves the
  device. A room created on the front page, or joined by pasting its link
  into Join, now gets the key in memory and never shows it in the address. A
  room opened from a clicked link has it removed as the page starts; the
  browser may still have recorded the address it was opened with, which no
  page can reach, so people at risk should paste links into Join. Copy link
  builds the full link from memory.
- **The server remembered every visitor's address until it restarted.**
  Nothing was logged or written to disk, but the rate-limit tables held each
  client's IP address in plain text and dropped entries only once a table
  reached 100,000 — which a server this size never does. So its memory held a
  list of everyone who had used it since boot. The tables now hold a keyed
  pseudonym instead (HMAC under a key drawn at startup and never written), and
  every minute they drop each entry that no longer limits anything, so a visit
  is remembered for about one limiter window — at most an hour — after it
  ends. Whoever captures the running process still holds the key and could
  test a suspected address; that is the floor for any server that rate-limits,
  and the reason to reach RÚNA over Tor if it matters.

- **Passphrase rooms never actually used Argon2id.** The Content Security
  Policy allowed `script-src 'self'`, which also forbids compiling
  WebAssembly, and Argon2id runs as WebAssembly. Every browser refused it, the
  client fell back to PBKDF2 at 600,000 iterations without saying so, and the
  room went on telling the server it used Argon2id. The policy now adds
  `'wasm-unsafe-eval'`, which permits compiling WebAssembly and nothing else;
  `eval` stays forbidden. The fallback is gone: a browser that cannot run
  Argon2id is refused with an explanation instead of being quietly given a
  weaker key. No existing room was affected past the next restart, since
  rooms live only in memory. A taken room name is now reported as taken
  before any key is derived.
- **One caller could lock everyone out of a room.** Join attempts were limited
  per room, in one window shared by everybody, and every attempt counted, not
  only failures. Anyone who knew a named room's name could spend it and keep
  every real join failing — which looks exactly like a wrong passphrase. The
  limit is now per caller, and a successful join no longer spends two
  attempts.
- **A room's key-derivation settings could reveal that it existed.** The
  metadata endpoint answers identically for real and missing rooms, but echoed
  a real room's own parameters while a missing one got the defaults. Creation
  now accepts only the standard parameters, so the two cannot differ. No room
  made through the interface was affected.
- **Dependencies with published advisories are upgraded**: vitest 4, vite
  6.4.4, KaTeX 0.18. Every alert but one was in build and test tooling. The
  one in shipped code, KaTeX, was not exploitable here — RÚNA sets
  `trust: false` itself and sanitises KaTeX's output afterwards — and math
  renders byte-for-byte as before.

### Added

- **RÚNA as a Tor onion service.** `RUNA_ONION=1 ./scripts/deploy-oracle.sh`
  sets up tor on the box and gives RÚNA an onion address, so someone who
  opens it through Tor never gives the server an IP address, and their
  network sees only that they use Tor. The onion listener treats each Tor
  circuit as its own client and believes no forwarded-for header, so one
  visitor can neither forge a fresh allowance nor spend everyone else's; tor's
  proof-of-work defence makes circuits costly to open in bulk. Clearnet pages
  send `Onion-Location`, so Tor Browser offers the onion address by itself.
  The client allows plain `ws://` on a `.onion` page, where Tor already
  encrypts and authenticates the whole path. Caddy and other sites on the box
  are untouched.

- **A security level for each room.** Whoever creates it chooses *Everyday*,
  where a refresh keeps you in the room, or *Highest security*. For a private
  room, Highest means the key is never stored on anyone's device, not even for
  the open tab: a refresh forgets it, and coming back means pasting the link
  into Join. For a shared room, whose address is its name, Highest keeps the
  name out of the address bar and browser history and asks the browser not to
  save the passphrase; a shared room opened from Join takes its name as its
  address only once the room has said it is everyday. The choice is sealed in the room's encrypted configuration, so it
  covers everyone who opens the room and the server cannot tell which rooms
  made which. A configuration that is missing or will not open is treated as
  Highest, so a server cannot downgrade a room by stripping it.

- **Join a room from the front page.** Paste the link someone sent you, or type
  a shared room's name. It reads links with their `https://` lost, bare room
  ids, old `/n/` addresses and stray spaces, says what it found before opening
  anything, and warns when a private link has lost its key.
- **Rooms survive a server restart.** Rooms still live only in memory, and the
  server still writes nothing down. With `RUNA_RESTART_KEY` set, the countdown
  before a restart now ends by handing every member a signed ticket for their
  room. When the new process comes up, their pages present it, the room is
  recreated under its old link, and each page sends its copy back — so a
  redeploy costs nobody their document, and someone who joins afterwards sees
  everything written before it. The countdown says which of the two is about
  to happen. Both deploy scripts generate the key once into a root-only file.
- **A connection nobody is typing into is checked every 15 seconds.** One that
  died quietly used to show the room as connected, while everyone else's edits
  went nowhere, until the next keystroke. Each answer also carries who is in
  the room, so a list that missed a join or a leave is corrected.
- **A restart warns every open room first.** On SIGTERM — what
  `systemctl restart`, `docker stop` and both deploy scripts send — every open
  room sees a countdown with an Export button, and the server waits it out
  (`RUNA_SHUTDOWN_GRACE_SECS`, 60 s by default). With nobody connected it stops
  at once. Room creation during the countdown is refused with a reason.
- **A refused connection says why.** Past the per-address or server-wide
  connection limit the socket used to close silently and the page retried
  forever with nothing on screen. It now closes with `4007` or `4008` and the
  page says which. The per-address limit was 10, which one office or mobile
  carrier could reach; it is 64 now, and configurable with
  `RUNA_MAX_CONNS_PER_IP`.
- **Signed bills of materials.** The SBOMs published with each release are
  signed with cosign the same way as the binaries, so a replaced one no longer
  goes unnoticed. [`SECURITY.md`](docs/SECURITY.md#release-integrity) shows how
  to verify them.
- **Fuzz targets for the code that can lose something**: log compaction, the
  only server path that discards data, and the room-creation body. Both were
  confirmed able to fail by reintroducing a bug in each.

### Fixed

- **Integral and sum limits rendered flat.** `$\int_0^\infty$` came out as
  "∫ 0 ∞": KaTeX writes a sub- and superscript on one base as `<msubsup>`,
  which the sanitizer did not allow, so it dropped the element and kept its
  children. `\boxed`, `\cancel` and `\hphantom` were lost the same way. The
  three elements are allowed now, `\boxed` keeps its `notation` so it is not
  drawn as a long division, and colour (`\colorbox`) stays out as `\color`
  always has.

- **"No expiry" said a room dies when everyone leaves, or at a restart.**
  It ends when shredded, or after sitting empty with no edits for 12 hours,
  and a restart hands it over like any other room. The README had briefly
  dropped the option altogether.

- **Edits could be lost four ways**: typing while offline, typing into a
  connection that had died without the browser noticing, typing just as a
  reconnect completed, and resending a large history after an outage. An edit
  now stays queued until the server confirms it has stored it, and is sent
  again on the next connection. A connection that stops confirming for 10
  seconds is replaced, and a resend too big for one message is split.

- **A shredded room could stay open.** The server destroys its copy once every
  connected person has agreed — and that included anyone who opened the room
  during the vote, who never saw the request and so could never agree. Every
  voter's page wiped itself and showed the room as gone, while it stayed open
  to anyone with the link. Someone who arrives mid-vote no longer counts, just
  as the voters' own pages already did not count them; the server takes its
  own note of who was present as the request passes through, so nobody can
  shrink that list. An unfinished set of agreements now expires after half a
  minute rather than five, so a stray one cannot stall the next shred.
- **Another website could lock visitors out of their rooms.** Any page could
  have its visitors' browsers send bad joins to RÚNA, spending their address's
  guess limit until their real rooms answered "no such room". Requests from
  other sites are refused now.

- **The second Paste button in Firefox and Safari.** It was never a second
  menu. Monaco's Paste item reads the clipboard from script, and those
  browsers answer every such read with a Paste button of their own that has to
  be clicked as well — a permission prompt no page can turn off, so no Paste a
  page draws itself can ever take one click there. Right-click in those two
  now opens the browser's own menu instead, over an invisible stand-in holding
  your selection: Cut, Copy, Paste and Select All, each one click, carried out
  on the editor. Change All Occurrences and Command Palette stay on ⌘F2/Ctrl+F2
  and F1. Chromium keeps the editor's menu, whose Paste asks once per site.
- **Long sessions stopped compacting their history, and could fill up.** A
  snapshot has to say how much of the room's log it covers, and a client could
  only count the edits it had written itself. The longer-present member, who
  takes the snapshots, might mostly have been reading — and once its count fell
  below the last snapshot's, the server refused every snapshot after it. The
  log then grew until edits were refused. The server now tells each client the
  log position of every update, and snapshots cover exactly what the client
  holds.
- **A live room could be reported as gone.** The server allows 30 join
  attempts a minute from one address, to slow anyone guessing at a room's
  key — and it counted successful joins too. So the 31st connection in a minute
  from one office, school or mobile-carrier address, as happens when a whole
  team reconnects after a network blip or a restart, was refused with the same
  answer as a room that does not exist, and the page said the room was gone.
  Only failed attempts count now.
- **A member being outvoted could block a shred.** A cancel was accepted from
  anyone, for any request, so under Majority or Threshold one person could end
  every vote the moment it opened. Only the person who made a request can
  cancel it now; everyone else still rejects it by voting.
- **A restart ticket outlived the rejoin it was for.** It is dropped once the
  room is back, so a room shredded after a restart cannot be brought back by a
  second restart inside the ticket's ten minutes.
- **IPv6 visitors are limited by their /64**, the block one household or server
  is normally given, instead of by each of its 2^64 addresses.
- **Joining a room with text in it showed an empty preview** until somebody
  typed. The text arrived while the editor was being attached, before the
  preview was listening for it.

### Changed

- **Browser tests run in Chromium, Firefox and WebKit** in CI, not Chromium
  alone. Lost edits above were found this way.
- **Fuzzing runs on demand** (Actions → fuzz → Run workflow) instead of every
  Monday. The Monday schedule keeps the supply-chain scan.
- **The server crate's licence metadata says Apache-2.0.** It said MIT, the
  upstream Rustpad licence, while `LICENSE` has always been Apache-2.0; SBOMs
  read this field.
- Playwright 1.63.

## 0.4.0

### Added

- **Bold and italic from the keyboard.** Ctrl/Cmd+B and Ctrl/Cmd+I. These were
  never Monaco keybindings — they are commands VS Code supplies for markdown,
  not part of the standalone editor — so in a markdown editor the two shortcuts
  everybody already has in their fingers did nothing at all. They run the same
  actions as the toolbar buttons, so the two cannot disagree about what bold
  means.

### Changed

- **Sticky scroll is off.** Monaco enables it by default: it pins the header of
  the enclosing foldable block to the top of the editor, which is useful in
  code, where a block is a function. Markdown has no folding rules in the
  standalone editor, so Monaco folds by indentation instead — and in prose,
  indentation means a list, a fenced code block, or pasted terminal output,
  none of which contain what follows them. It pinned rows of dashes and
  ordinary sentences, and cost up to 90px of editor height. The README explains
  how to turn it back on, and how to keep it while bounding the cost.
- **The tombstone says "Gone. Reduced to atoms."** It previously read
  "ROOM —— · SHREDDED —— UTC", where the dashes stood in for values no script
  ever supplied — the element was referenced nowhere — so every reader saw the
  placeholders themselves. They could not be filled either: the page is served
  with Clear-Site-Data and knows nothing about the room by design, and naming
  it on its own tombstone would write that address into a history just wiped
  for exactly that reason. It now says what is true, including the part the
  shred dialog says before you confirm: copies other people already made are
  not reachable from here.

### Fixed

- **The room is exactly as tall as the window.** The editor pane was a plain
  block holding the markdown ribbon and, beneath it, an editor sized at 100% of
  that same block — so the two came to a ribbon's height more than the window.
  The whole document scrolled: a second scrollbar beside the editor's own, and
  the status bar and ribbon sliding off the top as you scrolled. Reported as
  line numbers pinning themselves under the toolbar.
- **Right-click has a menu again.** Disabling Monaco's context menu to stop a
  doubling in Firefox and Safari removed the useful menu with it: on Monaco's
  rendered text the platform menu is a generic page menu with no Cut and no
  Copy, because the visible glyphs are divs and the real input is hidden.

### Known

- **A second context menu still appears in Firefox and Safari** alongside
  Monaco's, giving two Paste entries. Monaco calls preventDefault on the
  contextmenu event and measurement says it succeeds in all three engines, so
  whatever draws the second menu is not that event's default action. A second
  preventDefault of our own was tried and removed again: it changed nothing
  measurable, and shipping it would have been a placebo.

## 0.3.0

### Added

- **Export as Markdown.** The source exactly as typed, rather than what the
  preview made of it, so the file opens anywhere and comes back unchanged.
  The PDF is the export for reading; this is the export for keeping. The
  filename is a timestamp and carries no room identifier: a downloaded file
  outlives the room and lands where RÚNA has no reach, and naming it after
  the room would write that address into a downloads folder, a backup, and
  whatever syncs them.
- **Choose how much fits on a PDF page.** Compact, Normal or Large. The print
  stylesheet previously set page geometry but never a type size, so the PDF
  inherited the screen's typography and a 2,500-line document came out at
  sixty-odd pages with no recourse. Margins move with the type, because on A4
  the margins are a large share of the page and shrinking type alone buys far
  less than it appears to. Compact fits roughly twice as much per page as
  Large.
- **A divergent copy now repairs itself.** When copies disagree, the client
  asks the relay for the whole document — snapshot and full tail — instead of
  only reporting the problem. The warning appears when that did not work, and
  says so; it clears itself when the copies agree, and offers another attempt.
  Previously the only cure was reloading the page.

### Fixed

- **A shred request reached nobody after a reconnect.** Switching tabs and
  coming back left the previous connection's peer id in the roster for good,
  because the server's authoritative roster was merged into the client's
  rather than replacing it. Two reconnects meant four entries where two people
  were, so the vote asked three of four to approve — and because the roster's
  hash travels inside a signed shred request and every receiver re-derives it,
  an inflated roster hashed differently from everyone else's and every peer
  silently refused the request. A refusal to take part in a shred vote is also
  no longer discarded in silence.
- **The occupant count follows who is actually present.** It came from a
  join-time snapshot patched with the events a client happened to receive, so
  a missed departure over-counted for the rest of the session and four devices
  in one room could report four different numbers at the same moment.
- **A 24-hour room no longer accuses its own server of tampering.** The server
  reports the time remaining for an absolute expiry, which is necessarily less
  than the duration the room was created with, and the client compared the two
  directly — so every such room raised the tamper banner within a minute. A
  warning that is always on is worse than none. `JOIN_ACK` now carries how
  long the room has been alive so the two can be compared like with like, and
  a room that was legitimately extended is not flagged.

## 0.2.1

### Fixed

- **Line endings silently corrupted other peers' copies.** Monaco keeps one
  end-of-line sequence per document and rewrites inserted text to match it,
  while the shared document stores exactly what it is given. A client whose
  editor used CRLF — in practice, Windows — drifted one character per newline
  from everyone else, so text landed in the wrong place on other machines, a
  deletion removed the wrong range, and lines appeared merged on one client
  and separate on the rest. This is the reason to prefer 0.2.1 over 0.2.0.
- **The "your copy differs" warning fired on identical documents.** It
  compared the local document against hashes peers had broadcast up to a
  heartbeat earlier, on every update, and never cleared once raised — so two
  byte-identical copies could both display it for the rest of a session.
- **Equations rendered flat.** `$E = mc^2$` came out as "E=mc2" because
  KaTeX's HTML output positions superscripts with inline styles that the
  sanitizer correctly strips. Maths is emitted as MathML now, which carries
  the structure in the markup, needs no stylesheet and ships no fonts.
- **Preview mode showed the editor**, and no toggle looked selected. The
  layout control is now three tabs, one press each, with the active one
  marked.
- **Toolbar buttons ignored the selection.** Heading wrote the literal words
  "## Heading" over what you had selected, the code fence produced an empty
  fence with the line's text welded to its closing delimiter, and the task
  list inserted the word "task". The emphasis buttons left the caret outside
  the markers when nothing was selected.
- **The selected layout tab was outlined on three sides**, because adjacent
  tabs shared an edge by deleting one border.
- **Tapping a line on iOS zoomed the page** and left the shred dialog cropped,
  because the editor's hidden input sat below the 16px threshold at which
  Safari zooms on focus.
- **The occupant count** no longer comes from a roster snapshot that drifts.

### Changed

- The renderer no longer permits SVG at all. Those allowances existed solely
  for KaTeX's HTML output, which is no longer produced.

## 0.2.0

First public release. Multi-arch container image, keyless Sigstore signatures
on the binaries and the image, CycloneDX bills of materials for both halves,
and a landing page that fits on one screen.

**Superseded.** 0.2.0 contains the line-ending fault described under 0.2.1: a
Windows client joining a room silently corrupted every other participant's
copy. Do not run it.
