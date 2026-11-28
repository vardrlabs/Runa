# RÚNA

<p align="center">
  <strong>Ephemeral end-to-end encrypted collaborative markdown.</strong><br>
  The server cannot read what you write. The document lives only in RAM.<br>
  Any participant can burn it to nothing on demand.
</p>

<p align="center">
  <a href="https://runa.vardrlabs.com"><strong>Try it →</strong></a> ·
  <a href="#quick-start">Run your own</a> ·
  <a href="docs/THREAT_MODEL.md">Threat model</a> ·
  <a href="docs/SECURITY.md">Report a vulnerability</a>
</p>

---

> ### How this was built
>
> RÚNA was written collaboratively by **Prithvi Saha** (Vardr Labs) with
> **Claude Code** (Anthropic) and **GLM 5.3 Flash (Ox Alpha)**. Design,
> architecture, the security model and every decision about what ships were
> human; a large share of the implementation, the test suites and the audit
> passes were written with AI assistance, reviewed line by line before merge.
>
> This is stated plainly because it should inform how you read the rest.
> The security claims here do not rest on who typed them — they rest on
> `docs/THREAT_MODEL.md` saying what is and is not defended, on a test suite
> you can run yourself, and on `/version` letting you check that the code you
> audited is the code being served. Verify rather than trust; that advice
> would be identical if the whole thing had been written by hand.

---

## Try it without installing anything

A public instance runs at **[runa.vardrlabs.com](https://runa.vardrlabs.com)**,
and as a Tor onion service at:

```
http://xv5fx5v7kfatx7sg3ws7o3rqaixfndxmp2mplinkwdt67ghzi5rltgad.onion
```

Open the onion address in [Tor Browser](https://www.torproject.org/download/)
and the server never learns your IP address at all; Tor Browser also offers it
by itself when you visit the clearnet address. Check that it matches the
`Onion-Location` header runa.vardrlabs.com sends before trusting a copy of it
from anywhere else.

It is offered as a convenience and it is not special: it runs the same code in
this repository, and you can confirm which commit by visiting
[`/version`](https://runa.vardrlabs.com/version). Rooms there are subject to
the same rules as anywhere else — they live in RAM, they die on restart, and
nobody including us can read them.

If what you are writing genuinely matters, run your own. That is the entire
point of the project, and the next section takes about five minutes.

---

## Quick start

One command, if you have Docker:

```sh
docker run -d --name runa -p 127.0.0.1:3000:3000 \
  --memory=512m --memory-swap=512m --pids-limit=256 \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --ulimit memlock=-1:-1 \
  ghcr.io/vardrlabs/runa:latest
```

Then open <http://127.0.0.1:3000>. That is a complete, working RÚNA — no Rust,
no Node, no build.

It is bound to `127.0.0.1` on purpose. Browsers refuse `ws://` on anything but
loopback, so a real deployment needs TLS in front of it; see
[docs/DEPLOY.md](docs/DEPLOY.md), which does the whole thing including the
reverse proxy in one script.

**Verify what you just pulled:**

```sh
curl -s http://127.0.0.1:3000/version
```

`commit` and `bundle_sha256` should match the release you intended to run. If
`commit` reads `dev`, the image carries no provenance — do not trust it with
anything that matters.

Prefer a binary to a container? Signed builds for Linux and macOS are on the
[releases page](https://github.com/vardrlabs/Runa/releases), with cosign
signatures for the binaries and their SBOMs, and verification instructions in
[docs/SECURITY.md](docs/SECURITY.md#release-integrity).

Prefer to build it yourself? [Building from source](#what-you-need-before-you-start)
is below and takes about five minutes.

---

## Table of contents

- [Quick start](#quick-start)
- [What is RÚNA?](#what-is-rúna)
- [How it works (in plain English)](#how-it-works-in-plain-english)
- [What you need before you start](#what-you-need-before-you-start)
  - [Install Rust](#1-install-rust)
  - [Install Node.js](#2-install-nodejs)
  - [Verify everything works](#3-verify-everything-works)
- [Getting the code](#getting-the-code)
- [Running RÚNA on your computer](#running-rúna-on-your-computer)
  - [Start the server](#step-1-start-the-server)
  - [Start the web app](#step-2-start-the-web-app)
  - [Open it in your browser](#step-3-open-it-in-your-browser)
- [Using RÚNA](#using-rúna)
  - [Creating a room](#creating-a-room)
  - [Sharing a room](#sharing-a-room)
  - [Joining a room](#joining-a-room)
  - [Editing together](#editing-together)
  - [Editor settings you can change](#editor-settings-you-can-change)
  - [Shredding a room](#shredding-a-room)
- [Running the tests](#running-the-tests)
- [Deploying to the internet](#deploying-to-the-internet)
  - [Docker](#docker)
  - [Sizing it for the host](#sizing-it-for-the-host)
  - [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Troubleshooting](#troubleshooting)
- [Security: what this does and does not protect you from](#security-what-this-does-and-does-not-protect-you-from)
- [If your safety depends on it](#if-your-safety-depends-on-it)
- [Project structure](#project-structure)
- [Licence and attribution](#licence-and-attribution)

---

## What is RÚNA?

RÚNA is a shared notepad that you run on your own computer or server. Multiple
people can open the same document in their web browsers and type at the same
time, like Google Docs.

The difference is **privacy**. When you type into Google Docs, Google's servers
read every character. With RÚNA, your text is **encrypted inside your browser**
before it ever leaves your computer. The server that passes messages between
users sees only scrambled ciphertext — it mathematically cannot read what you
wrote.

When everyone is done, anyone can press **Shred**. This destroys the encryption
keys and wipes the server's copy. The document is gone — permanently, by design.

Think of it like passing locked envelopes between friends. The postal worker
(the server) delivers them but cannot open them. When you're done, everyone
burns their envelopes and throws away their keys.

## How it works (in plain English)

```
   Your browser                  Server                  Friend's browser
┌───────────────┐              ┌───────────────┐              ┌───────────────┐
│ You type      │              │ Stores        │              │ They see      │
│ "hello"       ├──encrypted──►│ scrambled     ├──encrypted──►│ "hello"       │
│               │    bytes     │ bytes         │    bytes     │               │
│ Has the key   │              │ Has NO key    │              │ Has the key   │
└───────────────┘              └───────────────┘              └───────────────┘
```

- Your browser encrypts every keystroke using a key derived from the room's
  secret link (or passphrase). The key **never leaves your browser**.
- The server receives encrypted bytes and forwards them to other people in the
  same room. It cannot decrypt them because it never had the key.
- Everyone in the room has the same key because they all opened the same
  secret link. Their browsers decrypt the messages and show the text.

For a detailed technical explanation of exactly how the cryptography works,
see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/PROTOCOL.md](docs/PROTOCOL.md).

---

## What you need before you start

You need three things installed on your computer:

| Tool | What it does | Version needed |
|---|---|---|
| [Rust](https://rustup.rs) | Compiles the server program | Install `rustup`; it fetches the pinned 1.98.0 for you |
| [Node.js](https://nodejs.org) | Runs the build tools for the web interface | 22 or newer |
| A web browser | To use the app | Chrome, Firefox, Safari, or Edge |

If you already have these installed, skip ahead to [Getting the code](#getting-the-code).
Otherwise, follow the steps below for your operating system.

### 1. Install Rust

#### macOS

Open **Terminal** (find it in Applications → Utilities → Terminal) and paste:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Press `1` (or Enter) when asked which installation option you want. Wait for it
to finish, then close and reopen Terminal so the changes take effect.

Verify it worked:

```sh
rustc --version
```

You should see something like `rustc 1.75.0` (the exact number doesn't matter,
as long as it's 1.70 or higher).

#### Linux (Ubuntu / Debian)

Open a terminal (`Ctrl+Alt+T` on most distributions) and paste:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify:

```sh
rustc --version
```

#### Linux (Fedora / RHEL)

```sh
sudo dnf install rust cargo
```

#### Windows

1. Go to [https://rustup.rs](https://rustup.rs)
2. Download and run `rustup-init.exe`
3. Press `1` (or Enter) when prompted
4. You may also need to install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) — the installer will tell you if so
5. Close and reopen Command Prompt or PowerShell

Verify in your new terminal window:

```powershell
rustc --version
```

### 2. Install Node.js

Go to [https://nodejs.org](https://nodejs.org) and download the **LTS** version
(the big green button). Run the installer with default settings.

Verify it worked by opening a new terminal window:

```sh
node --version
npm --version
```

You should see something like `v22.11.0` and `10.9.0`. If `node --version`
prints anything below `v22`, install the current LTS from the link above.

> **Windows note:** After installing Node.js, you may need to restart your
> computer before `node` is recognised in Command Prompt.

### 3. Verify everything works

Run these two commands one at a time. If both print version numbers without
errors, you're ready to continue.

```sh
rustc --version && cargo --version
node --version && npm --version
```

<details>
<summary>If something went wrong…</summary>

**"command not found" error:** The tool was installed but your terminal doesn't
know where to find it. Close ALL terminal windows and open a fresh one. On
Linux/macOS, also try running `source ~/.zshrc` or `source ~/.bashrc`.

**Rust says "linker not found":** On macOS, install Xcode command-line tools:
```sh
xcode-select --install
```
On Windows, install Visual Studio Build Tools from the link above.
On Linux, install the build essentials:
```sh
sudo apt install build-essential pkg-config libssl-dev
```
</details>

---

## Getting the code

### Option A: Using git (recommended if you plan to make changes)

```sh
git clone https://github.com/YOUR_USERNAME/Runa.git
cd Runa
```

(Replace `YOUR_USERNAME` with your GitHub username after you fork the repo.)

### Option B: Download as ZIP (no git required)

1. Go to the repository page on GitHub
2. Click the green **Code** button → **Download ZIP**
3. Unzip the file somewhere you can find it (like your Desktop)
4. Open a terminal and navigate into the folder:

```sh
cd ~/Desktop/Runa-main     # macOS / Linux
cd Desktop\Runa-main       # Windows PowerShell
```

---

## Running RÚNA on your computer

There are two programs to start: a **server** (Rust) and a **web app**
(Node.js). You need both running at the same time, each in its own terminal
window or tab.

### Step 1: Start the server

Open a terminal in the project folder and run:

```sh
cargo run --release -p runa-server
```

The first time you do this it will take **several minutes** because Rust needs
to compile every dependency from source. Subsequent starts will be much faster
(just a few seconds).

When it's ready you'll see:

```
INFO runa_server: runa server listening addr=127.0.0.1:3000
```

**Leave this terminal open and running.** If you close it, the server stops.

<details>
<summary>What just happened?</summary>
Cargo downloaded ~200 Rust packages (called "crates"), compiled them along
with the RÚNA server code, optimised everything for release, and produced an
executable binary at <code>target/release/runa-server</code>. It then ran that
binary, which started listening for connections on port 3000.
</details>

### Step 2: Start the web app

Open a **second** terminal window (don't close the first one!) and run:

```sh
cd web
npm ci
npm run dev
```

Again, the first time will take a minute or two while npm downloads packages.

When it's ready you'll see something like:

```
VITE v6.0.6  ready in 500 ms
➜  Local:   http://localhost:5173/
```

**Leave this terminal open too.**

<details>
<summary>What just happened?</summary>
<code>npm ci</code> downloaded ~400 JavaScript packages into a folder called
<code>node_modules</code>. Then <code>npm run dev</code> started Vite, a
development server that compiles the React/TypeScript code in real time and
serves it at port 5173. It also proxies API calls and WebSocket connections
to the Rust server on port 3000, so the two programs work together seamlessly.
</details>

### Step 3: Open it in your browser

Open your web browser and go to:

```
http://localhost:5173
```

You should see the RÚNA landing page with a dark background, a choice between
**UNLISTED** and **NAMED** rooms, and a **Join a room** box.

🎉 **That's it!** Continue to [Using RÚNA](#using-rúna) below.

---

## Using RÚNA

### Creating a room

1. On the landing page, choose **UNLISTED** (default, recommended) or **NAMED**

   | UNLISTED | NAMED |
   |---|---|
   | Nobody can find this room | Anyone who knows the name can find it |
   | The link contains the secret key | Protected by a passphrase |
   | Share by sending the full link | Share by saying the name + passphrase |
   | Best for most uses | Best when you need to speak the address aloud |

2. Pick an expiry time (how long until the room self-destructs):
   - **30 min / 1 hour / 8 hours** after last activity
   - **24 hours** from creation
   - **No expiry** — until it is shredded, or has sat empty with no edits for
     12 hours (`RUNA_IDLE_CEILING`)

   Whichever you pick, a room also ends the moment you shred it. A server
   restart no longer has to end it — see
   [Running the server behind it](#running-the-server-behind-it).

3. Pick the room's **Security**:
   - **Everyday** (default) — a refresh keeps you in the room.
   - **Highest security** — choose this when someone could be harmed by being
     linked to the room.
     - *Private room:* the key is never stored on anyone's device, even for
       the open tab. A refresh forgets it; coming back means pasting the link
       into **Join a room**.
     - *Shared room:* the room's name never goes in the address bar or
       browser history, and the browser is asked not to save the passphrase.
       A refresh leaves the room; coming back means typing its name into
       **Join a room**.

   Either way, a private room's key never sits in the address bar or the
   browser's history, and a shared room's passphrase is never stored. The
   setting is sealed inside the room's encrypted configuration, so it applies
   to everyone who opens the room — and the server cannot tell which rooms
   chose which.

4. Click **Create private room** or fill in a name + passphrase and click
   **Create shared room**

### Sharing a room

Click **Copy link** in the status bar. You get something like:

```
http://localhost:5173/r/a1b2c3d4e5f6...#k=AbCdEf123456&s=GhIjKl789012
```

**The entire link including everything after the `#` is the room's key.** Send
the whole thing to people you want to invite. Don't copy it from the address
bar: RÚNA keeps the key out of there, so the address alone is `/r/…` with no
key, and won't open the room.

> ⚠️ **Important:** Some chat apps (Slack, Discord, Teams) strip the part
> after the `#`. Always test the link yourself before sharing it, or copy-paste
> it manually rather than clicking a preview.

For **named rooms**, share the name and passphrase separately — like telling
someone "go to copper-lantern and the password is harbor thistle quartz nine."

### Joining a room

Opening the link is enough. If you were sent it in a form your browser will not
open directly, paste it into **Join a room** on the front page. That box
accepts:

- a whole link, or one whose `https://` got lost on the way
- a `/r/…` path, or a bare room id with or without its `#k=…`
- a shared room's name, its full address, or an old `/n/` address
- stray spaces and capitals

It tells you what it found before opening anything, and warns you if a private
link has lost its key — in which case ask for the link again, whole.

### Editing together

Everyone who opens the same link sees the same document. Changes appear in
real-time (within about 100 ms on a local network). The status bar at the top
shows how many people are connected.

Every 15 seconds the page checks that its connection is still alive, so one
that died quietly is noticed and reconnected rather than showing you as
connected while your edits go nowhere. The same check corrects the list of
who is in the room.

### Editor settings you can change

The editor is [Monaco](https://microsoft.github.io/monaco-editor/), the one
from VS Code, and its options live in one object — `MONACO_OPTIONS` at the
bottom of `web/src/routes/Room.tsx`. Change a value there, rebuild the web app,
and it takes effect. Every option Monaco supports is listed in
[its documentation](https://microsoft.github.io/monaco-editor/typedoc/interfaces/editor.IEditorOptions.html).

Two that are deliberately not at their defaults:

**Sticky scroll** — off. Monaco turns this on by default: it pins the header
of whatever foldable block you are inside to the top of the editor. That is
useful in code, where a block is a function. Markdown has no folding rules in
the standalone editor, so Monaco falls back to folding by indentation — and in
prose, indentation means a list, a fenced code block, or pasted terminal
output, none of which are containers for what follows them. The result was
arbitrary lines pinned to the top, costing up to 90 px of editor height. Turn
it back on by setting:

```ts
stickyScroll: { enabled: true },
```

You can also keep it and bound the cost with `{ enabled: true, maxLineCount: 1 }`,
which pins one line rather than the whole enclosing chain.

**Layer hinting** — left at Monaco's default. It was briefly disabled to chase
a rendering fault that turned out to be sticky scroll, and putting it back
restored GPU-composited scrolling on large documents.

### Shredding a room

Click the red **Shred** button in the top-right corner. This opens a dialog
explaining what will happen. In a multi-person room, **everyone must agree**
before the shred executes — one person pressing the button alone does nothing
unless they're the only one there.

The agreement is enforced against the other people in the room: a peer cannot
shred alone, cannot forge your approval, and cannot claim a lower threshold
than your own view of the room supports. It is **not** enforced against
whoever runs the server, because the server is what tells your browser who the
peers are — substitute the keys and a unanimous vote can be manufactured. That
costs a hostile operator nothing they did not already have, since they hold the
encrypted log and can simply drop it, and it reveals nothing, since they never
hold a key. [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) sets out where the line
falls. If it matters to you, run the server yourself.

When the shred completes, every browser is redirected to a tombstone page that
says *"Gone. Reduced to atoms."* The encryption keys are gone. There is no undo.
The page names neither the room nor the time — it is served with
`Clear-Site-Data`, and putting the room's address on its own tombstone would
write it into a history that was just wiped for exactly that reason.

---

## Running the tests

The fastest check is the verification script. It runs the server tests, clippy,
the Linux cross-compile check, the web suite, type checking, linting, the
production build, a check that the built page loads nothing from third-party
origins, an end-to-end smoke test against a real server, and a real-browser
test — stopping at the first failure:

```sh
./scripts/verify.sh
```

It ends with `VERIFIED` if everything passed. Every pull request is expected
to pass it. The supply-chain scans (`cargo-deny`, `cargo-audit`) run in CI, on
every pull request and every Monday.

To run the suites separately:

```sh
# Terminal 1: Server tests
cd /path/to/Runa
cargo test -p runa-server

# Terminal 2: Web tests
cd /path/to/Runa/web
npm ci          # only needed once, or if package.json changed
npx vitest run
```

You should see all tests pass. The server has 70 unit tests and 48 integration
tests. The web suite has 247 tests covering cryptography, transport, document
convergence, rendering security, and shred consensus.

There are also four `cargo-fuzz` targets in `server/fuzz/` (frame headers, room
names, log compaction, and the room-creation body). They are not part of the
normal run. In CI, start them from **Actions → fuzz → Run workflow**; about
45 minutes. Locally, with a nightly toolchain:

```sh
cd server
cargo install cargo-fuzz
cargo +nightly fuzz run frame_header -- -max_total_time=300
```

---

## Deploying to the internet

> **Deploying to a VM you share with other services?** Use
> [`docs/DEPLOY.md`](docs/DEPLOY.md) and the one command it wraps:
>
> ```sh
> ./scripts/deploy-oracle.sh
> ```
>
> It builds the bundle locally, ships the committed tree, builds on the box,
> installs a hardened systemd unit with a bounded memory ceiling, wires the
> reverse-proxy vhost behind a validate-and-rollback guard, and then proves
> the deployment from outside. Re-run it to ship an update.

The instructions above run RÚNA locally. To put it on the internet where
other people can reach it, you have two options:

### Docker

This is the easiest way to deploy. You need [Docker](https://docs.docker.com/get-docker/)
installed on your server. Use the signed image, or build your own from the
project root with `docker build -t runa .` and put `runa` in place of the image
name below.

```sh
# Generate the restart key once, and keep it: a new key cannot read tickets
# signed under the old one, so changing it ends every open room.
mkdir -p ~/.runa && chmod 700 ~/.runa
(umask 077; printf 'RUNA_RESTART_KEY=%s\n' \
  "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')" > ~/.runa/restart.env)

docker run -d --name runa \
  --restart unless-stopped \
  --stop-timeout 90 \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m --memory-swap=512m \
  --pids-limit=256 \
  --ulimit memlock=-1:-1 \
  --env-file ~/.runa/restart.env \
  -e RUNA_TRUSTED_PROXY=1 \
  -p 127.0.0.1:3000:3000 \
  ghcr.io/vardrlabs/runa:latest
```

This runs the server with:
- No write access to disk (nothing can persist)
- No Linux capabilities (minimal attack surface)
- No privilege escalation possible
- Memory capped at 512 MB, with swap disabled and the process's memory locked
  so key material cannot reach swap
- Process count limited to 256
- 90 seconds to stop, so the 60-second restart countdown is never cut short —
  Docker's default of 10 would kill it mid-warning
- A restart key, so open rooms carry over a `docker restart` or an upgrade

It listens on `127.0.0.1:3000` only, for a reverse proxy to put TLS in front of
it — see [Behind a reverse proxy](#behind-a-reverse-proxy). Without a proxy,
drop `-e RUNA_TRUSTED_PROXY=1`. `./scripts/deploy-docker.sh` does all of this,
plus the proxy, in one command.

### Sizing it for the host

Rooms live entirely in RAM, so "how much memory can strangers make this process
hold" is a number you set, not one you discover. The server prints its ceiling
at startup:

```
resource ceiling: retained ciphertext will not exceed max_total_log_mib across
all rooms  max_rooms=512 max_log_mib_per_room=32 max_total_log_mib=512
```

`RUNA_MAX_TOTAL_LOG_MB` is the one that actually bounds the process. The
per-room limit only caps a single document; the total is what a host shared
with anything else needs.

| Variable | Default | What it bounds |
|---|---|---|
| `RUNA_MAX_TOTAL_LOG_MB` | `512` | **Ciphertext retained across all rooms.** The real memory ceiling |
| `RUNA_MAX_ROOMS` | `512` | Live rooms. Creation returns `503 AT_CAPACITY` past this |
| `RUNA_MAX_LOG` | `33554432` | Bytes of history in one room, before snapshot compaction |
| `RUNA_MAX_PEERS` | `32` | Connections per room |
| `RUNA_MAX_FRAME` | `1048576` | Bytes in one WebSocket message |
| `RUNA_FRAME_RATE` | `100` | Frames one connection may send in a second, with a burst of twice that. A connection that goes past it is closed with 4002. Never below 25, which is what the page needs for cursor movement and typing |
| `RUNA_BYTE_RATE` | `1048576` | Bytes one connection may send in a second, with a burst of twice that. Raised to at least half of `RUNA_MAX_FRAME`, so that one full frame always fits in the burst, and never below 4096 |
| `RUNA_MAX_CONFIG_BLOB` | `4096` | Bytes of encrypted room config held for the room's life |
| `RUNA_MAX_CONNECTIONS` | `1024` | Concurrent sockets, process-wide. The per-IP limit bounds one address; this bounds the sum |
| `RUNA_MAX_CONNS_PER_IP` | `64` | Concurrent sockets one address may hold, at most a quarter of `RUNA_MAX_CONNECTIONS`. Offices and mobile carriers put many people behind one address |
| `RUNA_SHUTDOWN_GRACE_SECS` | `60` | On SIGTERM, how long every open room is shown a countdown before the process stops. `0` stops at once |
| `RUNA_RESTART_KEY` | unset | 64 hex characters. Lets open rooms carry over a restart: the stopping process hands each member a ticket signed with it, and the next process, holding the same key, takes the room back from their copies. Unset, a restart ends every room. A secret; both deploy scripts generate it once into a root-only file and never rotate it |
| `RUNA_MAX_QUEUE_KB` | `4096` | Bytes one connection may have queued but not yet written to its socket. Floored at twice `RUNA_MAX_FRAME`, so raising the frame cap raises this too |
| `RUNA_ROOMS_PER_HR` | `20` | Unlisted rooms one address may create per hour |
| `RUNA_NAMED_PER_HR` | `5` | Named rooms one address may create per hour |
| `RUNA_IDLE_CEILING` | `43200` | Seconds an unattended `ttl: none` room survives |
| `RUNA_ONION_BIND` | unset | A second listener, loopback only, for a Tor onion service. Expects tor's `HiddenServiceExportCircuitID haproxy`, treats each circuit as its own client, and believes no forwarded-for header. See [DEPLOY.md](docs/DEPLOY.md#onion-service) |
| `RUNA_ONION_URL` | unset | `http://<56 characters>.onion`. Sent to Tor Browser on clearnet pages as `Onion-Location` |
| `RUNA_ALLOW_CEILING_OPTOUT` | unset | Set to `1` to let clients create rooms that never expire. **Off by default** — an immortal room is a permanent memory reservation any anonymous caller could make |

Sizing for a small shared VM — say 1 GB, with other services on it:

```sh
RUNA_MAX_TOTAL_LOG_MB=128 RUNA_MAX_ROOMS=64 RUNA_MAX_PEERS=16 \
RUNA_MAX_CONNECTIONS=256 RUNA_MAX_QUEUE_KB=2048 \
RUNA_TRUSTED_PROXY=1 RUNA_BIND=127.0.0.1:3000 RUNA_DIST=web/dist \
  ./runa-server
```

That works out to roughly `25 + 179 + 512 + 32 ≈ 748 MB` worst case. The
queue term dominates once `RUNA_MAX_FRAME` is 1 MiB, because a queue has to
hold at least two frames — drop `RUNA_MAX_CONNECTIONS` before dropping
`RUNA_MAX_QUEUE_KB`, since a queue below one frame cannot accept anything.

The worst case has a closed form, which is the point of the last two:

```
peak ≈ 25 MB baseline
     + 1.4 × RUNA_MAX_TOTAL_LOG_MB      (entry overhead and allocator slack)
     + RUNA_MAX_CONNECTIONS × RUNA_MAX_QUEUE_KB
     + ~32 MB rate-limiter tables, fully saturated
```

The 1.4 factor is because the budget counts frame bytes; each log entry also
carries a 56-byte record and its own allocation. Frames queued for a peer that
has stopped reading are *not* retained history, so nothing else accounts for
them — hence the per-connection byte cap rather than a frame count.

> On Linux the server calls `mlockall(MCL_CURRENT | MCL_FUTURE)` so key
> material cannot reach swap. It needs a raised `RLIMIT_MEMLOCK` (or
> `CAP_IPC_LOCK`) to take effect, and gets neither by default — under Docker's
> 64 KB limit, or systemd's `DynamicUser=yes`, the call fails with `ENOMEM`.
>
> Both shipped deploy paths now raise it (`--ulimit memlock=-1:-1` for the
> container, `LimitMEMLOCK=infinity` for the unit), and the server says at
> startup which way it went:
>
> ```
> INFO  memory locked; this process will not be swapped
> WARN  mlockall failed: this process CAN be swapped to disk …
> ```
>
> If you see the warning on a host with swap enabled, the no-swap guarantee is
> not holding. Keep the log budget well under the host's RAM either way —
> locked pages cannot be reclaimed under pressure.

### Behind a reverse proxy

Any real deployment needs HTTPS in front of RÚNA — the browser refuses `ws://`
on anything but loopback, so without TLS the editor simply will not connect.

> **Required behind any proxy: `RUNA_TRUSTED_PROXY=1`.**
>
> Every per-IP rate limit keys on the address RÚNA sees. Behind a proxy that
> address is the loopback for *every* visitor, so all the limits in `config.rs`
> collapse into one shared bucket — once 64 people are connected, the next is
> refused a WebSocket because the whole server has "used up" one address's
> allowance (`RUNA_MAX_CONNS_PER_IP`). With
> this variable set, RÚNA keys the limits on the last `X-Forwarded-For` entry
> instead. That value is used in memory as a limiter key and is never logged.
>
> Leave it **off** when RÚNA is exposed directly, or anyone can forge the header
> and get a fresh bucket per request.

#### Caddy (recommended)

Caddy is the better fit here for one specific reason: **it does not log
requests unless you ask it to.** RÚNA's URLs contain the room ID, which is the
secret, so a proxy that writes request paths to disk by default is a
liability. Caddy also obtains and renews Let's Encrypt certificates on its own.

```caddyfile
runa.example.com {
    # No `log` directive, deliberately. The request path contains the room ID.
    tls {
        protocols tls1.3 tls1.3
    }
    reverse_proxy 127.0.0.1:3000
}
```

Point an A record at the machine, run `caddy run --config Caddyfile`, and the
certificate is issued on first request.

#### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name runa.example.com;

    ssl_certificate     /etc/letsencrypt/live/runa.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/runa.example.com/privkey.pem;
    ssl_protocols TLSv1.3;

    # The request path contains the room ID, which is a secret. nginx logs
    # every path by default, so this line is a security control, not a
    # preference. Do not remove it to "debug something quickly".
    access_log off;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;

        # RÚNA reads this only when RUNA_TRUSTED_PROXY=1, and only ever as an
        # in-memory rate-limit key. It is never written anywhere.
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

#### Running the server behind it

Bind RÚNA to the loopback interface so it is reachable only through the proxy:

```sh
cd web && npm ci && npm run build && cd ..
RUNA_TRUSTED_PROXY=1 RUNA_DIST=web/dist RUNA_BIND=127.0.0.1:3000 \
  cargo run --release -p runa-server
```

Or with Docker: the command under [Docker](#docker) already binds to loopback
and sets `RUNA_TRUSTED_PROXY=1`.

> Rooms live only in RAM, and the server never writes one to disk. What lets a
> room outlive a restart is the people in it: they hold the document and the
> key, and with `RUNA_RESTART_KEY` set the server hands them the means to bring
> it back.
>
> On SIGTERM, which `systemctl restart`, `docker stop` and both deploy scripts
> send, every open room is shown a countdown (`RUNA_SHUTDOWN_GRACE_SECS`, 60 s by
> default), and the process waits it out. Then every member still connected is
> handed a signed ticket for their room and disconnected. When the new process
> comes up with the same key, their pages present the ticket, the room is
> recreated under its old link, and each page sends its copy back — so nobody
> loses anything, and someone who joins afterwards sees everything written
> before the restart. See amendment I in [PROTOCOL.md](docs/PROTOCOL.md).
>
> What still ends a room: a restart without the key, a room nobody had open at
> that moment, and a reboot or a killed process, which skips the handover
> altogether. So deploy at a quiet time all the same.

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `cargo: command not found` | Rust isn't in your PATH | Close and reopen your terminal, or run `source ~/.cargo/env` |
| `npm: command not found` | Node.js isn't installed or PATH issue | Reinstall Node.js, restart terminal |
| Port 3000 already in use | Something else is listening on that port | Kill the other process or set `RUNA_BIND=127.0.0.1:3001` and update the Vite proxy target |
| Browser shows blank page | The web app isn't running | Make sure `npm run dev` is still running in its own terminal |
| Blank page from a deployed server | `RUNA_DIST` does not point at a built bundle | Run `npm run build` in `web/` and set `RUNA_DIST=web/dist`. The server logs a warning at startup when it cannot find `index.html` |
| "This page is not on HTTPS" | Serving over plain `http://` on a public hostname | Browsers refuse `ws://` from such a page. Put TLS in front — see [Behind a reverse proxy](#behind-a-reverse-proxy). `localhost` is exempt |
| Room creation fails with `AT_CAPACITY` | The server is at `RUNA_MAX_ROOMS` | Raise it if the host has the memory, or wait for rooms to expire |
| Only one client can connect behind a proxy | `RUNA_TRUSTED_PROXY` is not set | Every request appears to come from the proxy, so all clients share one rate-limit bucket. Set `RUNA_TRUSTED_PROXY=1` |
| "Your network already has as many connections to this server as one address may" | More than `RUNA_MAX_CONNS_PER_IP` sockets from one address: many people behind one office or carrier address, or `RUNA_TRUSTED_PROXY` missing behind a proxy | Set `RUNA_TRUSTED_PROXY=1` behind a proxy; raise `RUNA_MAX_CONNS_PER_IP` if many people genuinely share an address |
| Browser shows "Connection refused" | The Rust server isn't running | Check that `cargo run --release -p runa-server` is still active |
| "This link is missing its key" | You refreshed a **Highest security** room, which forgets its key by design — or the `#k=…&s=…` part was stripped from the link | Paste the full link into **Join a room**. If you don't have it, ask whoever shared the room for the whole link, including everything after the `#` |
| Copying the address bar gives a link that doesn't open the room | RÚNA keeps the key out of the address bar | Use **Copy link** in the room's status bar |
| "This server is at its connection limit. Retrying…" | The server is at `RUNA_MAX_CONNECTIONS` | It retries on its own. On your own server, raise the limit if the host has the memory — see [Sizing it for the host](#sizing-it-for-the-host) |
| "This server is restarting for an update. Try again in a minute." | You tried to create a room during a restart countdown | Wait a minute. Rooms that were open carry over if the server has `RUNA_RESTART_KEY` set |
| "This browser could not run Argon2…" | The browser cannot run the WebAssembly that protects a named room's passphrase, or ran out of memory doing it | Use an up-to-date browser and close other tabs. RÚNA refuses rather than falling back to a weaker key |
| A self-hosted page cannot create or join rooms; the server answers `403` | The request came from a different site than the server's own address — for example a dev page on another port without the Vite proxy | Open the page from the server's own address, or through `npm run dev`, whose proxy keeps the same host |
| Compilation errors mentioning OpenSSL | Missing system libraries | macOS: `brew install openssl` · Ubuntu: `sudo apt install libssl-dev pkg-config` · Fedora: `sudo dnf install openssl-devel` |
| `npm ERR!` during install | Corrupt cache or network issue | Try `rm -rf node_modules package-lock.json && npm install`, or check your internet connection |

---

## Security: what this does and does not protect you from

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full picture. Here
are the two sentences that matter most:

1. **A malicious server operator can serve you modified JavaScript.** This is
   true of every browser-delivered end-to-end-encrypted application. Self-host
   if you don't trust whoever runs the server.

2. **Shredding removes the shared copy, not copies on other people's machines.**
   Anyone who could read the document can screenshot it or copy-paste it.
   RÚNA cannot reach into someone else's computer.

### What RÚNA *does* protect against

| Threat | Protection |
|---|---|
| Passive network eavesdropper | AES-256-GCM encryption on every frame, independent of TLS |
| Honest-but-curious server admin | Server stores only ciphertext; keys never leave browsers |
| Brute-force room guessing | 128-bit unguessable IDs + Argon2id KDF + rate limiting + timing-floor auth |
| Post-hoc disk forensics | No database, no files written, memory-hardened process, core dumps disabled |
| Malicious peer forging shred votes | Client-side signature verification, frozen roster hashes, fail-closed deadlines |

### What RÚNA does *not* protect against

| Threat | Why not |
|---|---|
| Someone screenshots the document | RÚNA controls its own page, not other applications |
| Malware on a participant's computer | Out of scope — use a clean machine |
| Traffic correlation (who talks to whom, when) | Use Tor Browser if this matters to you — see [If your safety depends on it](#if-your-safety-depends-on-it) |
| Someone with access to your browser history | The full link, key included, is recorded there; use a private window or Tor Browser |
| The server serving modified JS | See [the honest limit](docs/THREAT_MODEL.md#the-honest-limit-a-malicious-server-can-serve-you-bad-javascript) in THREAT_MODEL — this is inherent to browser-delivered apps |

---

## If your safety depends on it

RÚNA was built so that people can write together without the server, or anyone
who seizes it, being able to read what they wrote, and so that the document
can be destroyed when it has done its job. That makes it useful to journalists,
organisers and sources working where writing the wrong thing is dangerous.

It is also one tool, not a guarantee, and the gaps matter most to exactly those
people. Read this before relying on it.

**What it does for you**

- The server never holds a key. It relays ciphertext, keeps it only in RAM,
  and writes nothing to disk. Seizing the server yields no document.
- It logs no IP addresses, and does not keep them in readable form even in
  memory: rate limits work on a keyed pseudonym, forgotten about an hour
  after you leave at most. Someone who captures the running server could
  still test whether a particular address used it recently — which is why
  Tor, below, matters.
- No accounts, no email, no phone number, no analytics, no cookies.
- Shred destroys the shared copy for everyone, on everyone's agreement.

**What it does not hide**

- **That you used it.** Your network provider, and anyone watching it, can see
  that you connected to the server's address, when, and for how long. A
  censor can block the address outright.
- **The link is the key.** Anyone who gets the full link can read the room.
  That includes anyone who can read the chat where it was sent.
- **A clicked link may already be in your history.** RÚNA never leaves the
  key in the address bar, and a room opened from the front page — created
  there, or joined by pasting the link — never puts it there at all. But when
  you *click* a link, your browser may record it, key included, before RÚNA's
  page has loaded. With browser sync on, that history can leave your device.
- **Copies outside RÚNA.** Screenshots, the clipboard, exported PDFs, and
  anything on a seized or compromised device are beyond its reach.
- **Whoever runs the server.** A malicious or compelled operator can serve you
  modified JavaScript. That is true of every browser-based encrypted tool.

**If you are at risk**

1. **Open RÚNA in [Tor Browser](https://www.torproject.org/download/).** That
   hides that you connected, gets past simple blocking, and keeps no history.
   If the server has an onion address, Tor Browser offers to switch to it —
   accept, and the server never learns an IP address for you at all.
   RÚNA needs JavaScript, so it will not run at Tor Browser's *Safest*
   security level. Failing Tor, at least use a private window, which also
   keeps no history.
2. **Paste links into Join a room instead of clicking them**, so the key
   never enters your browser's history. Make rooms for people at risk with
   **Highest security**, so nothing on their device keeps the key either.
3. **Run your own server**, or use one run by someone you trust. The
   [Quick start](#quick-start) is one command.
4. **Send the link only over an end-to-end encrypted channel with
   disappearing messages**, and never in the same message as anything that
   identifies the room's purpose.
5. **Use a named room's passphrase only out loud or in person**, never
   alongside its name.
6. **Shred when you are done**, and close the browser.

If you work in a place where this matters and something here is unclear or
wrong for your situation, say so in a [private report](docs/SECURITY.md) —
it is treated as a security issue.

---

## Project structure

```
Runa/
├── server/                  Rust backend (the blind relay)
│   ├── src/
│   │   ├── main.rs          Entry point, router, signal handling
│   │   ├── config.rs        All limits as env-overridable constants
│   │   ├── memguard.rs      mlockall, core-dump suppression (Linux)
│   │   ├── bifrost/         WebSocket relay, frame codec, HTTP API
│   │   ├── heimdall/        Auth verification, rate limiting
│   │   ├── runar/           Room lifecycle, ciphertext log, name registry
│   │   ├── gjallarhorn/     Shred frame relay (counts nothing)
│   │   └── surtr/           Purge (one code path ends a room's life)
│   ├── fuzz/                Fuzz targets for the frame parser
│   └── tests/               Integration tests (real WebSocket clients)
├── web/                     Frontend (React + TypeScript)
│   ├── src/
│   │   ├── crypto/          Argon2id, HKDF, AES-GCM, identity, fingerprints
│   │   ├── transport/       Frame encoding, WebSocket client, reconnect
│   │   ├── doc/             Yjs CRDT wrapper, Monaco binding, awareness
│   │   ├── render/          Markdown pipeline with sanitiser-last ordering
│   │   ├── shred/           Consensus machine, roster hashing, wipe sequence
│   │   ├── routes/          Landing page, Join box, editor room
│   │   ├── ui/              Status bar, quorum dial, shred modal
│   │   └── export/          PDF export via Paged.js
│   └── scripts/             E2E smoke tests, SRI injection, origin checker
├── docs/                    Public documentation
│   ├── THREAT_MODEL.md      What RÚNA defends against (and what it doesn't)
│   ├── SECURITY.md          Reporting vulnerabilities, verifying releases
│   ├── PROTOCOL.md          Wire format specification and its amendments
│   ├── DEPLOY.md            Putting it on a VM, and why it is done that way
│   └── ATTRIBUTION.md       Upstream credits and dependency licences
├── deploy/                  systemd unit, env template, Caddy vhost
├── scripts/
│   ├── verify.sh            One-command check: tests, lint, build, end to end
│   ├── deploy-oracle.sh     Deploy to any Ubuntu VM as a hardened systemd unit
│   ├── deploy-docker.sh     The same, as a container
│   └── rollback-*.sh        Undo either
├── .github/workflows/       CI, signed releases, on-demand fuzzing
├── Dockerfile               Distroless production image
├── deny.toml                Bans database crates, enforces licences
├── NOTICE                   Copyright, and Rustpad's MIT notice
└── LICENSE                  Apache-2.0
```

---

## Licence and attribution

RÚNA is licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE).
Copyright 2026 Vardr Labs LLC.

It derives from [Rustpad](https://github.com/ekzhang/rustpad) by Eric Zhang,
which is MIT-licensed. Rustpad's operational transform engine was replaced with
an encrypted CRDT relay; Rustpad's MIT notice is reproduced in full in
[`NOTICE`](NOTICE) and continues to apply to the portions derived from it. If
you redistribute RÚNA or a fork of it, Apache-2.0 requires you to carry
`NOTICE` along. See [`docs/ATTRIBUTION.md`](docs/ATTRIBUTION.md) for what was
kept, what was removed, and what was added. This project does not imply
upstream endorsement.

---

<div align="center">
<em>RÚNA · Nothing here anymore.</em>
</div>
