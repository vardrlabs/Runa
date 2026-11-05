# Deploying RÚNA

This is the path for a small VM shared with other services. It is what the
`scripts/deploy-oracle.sh` script automates; read this once, then use the
script. Despite its name the script is not tied to Oracle Cloud — any Ubuntu
VM you can SSH into with `sudo` will do.

## Two supported paths

| | Command | Needs on the box |
|---|---|---|
| **Docker** — own image, own namespace, nothing else installed | `./scripts/deploy-docker.sh` | Docker |
| **systemd** — no daemon added, tighter syscall confinement | `./scripts/deploy-oracle.sh` | rustup |

Both bind to loopback and sit behind the same reverse proxy. Neither is
obviously better; they isolate different things.

**Docker** keeps RÚNA's filesystem, processes and toolchain entirely separate
from whatever else the box runs, and `docker rm -f runa` leaves nothing
behind. The honest cost is that installing Docker adds a root daemon and
rewrites `iptables`. That is a real change to a shared machine, and it is why
the deploy publishes to `127.0.0.1:3000` rather than `0.0.0.0:3000` — bound
to loopback, the container is unreachable from outside whatever happens to
the firewall rules.

**systemd** adds no daemon and confines the process more tightly than a
default container does: `DynamicUser=yes`, an empty capability bounding set,
a syscall filter, `ProtectSystem=strict`. The cost is a Rust toolchain on the
box and a build that competes for CPU with whatever else runs there.

Pick Docker for operational isolation, systemd for process confinement.

## What you need

- A domain pointed at the box with an **unproxied** A record.
- A reverse proxy terminating TLS. The browser refuses `ws://` on anything
  but loopback, so without TLS the editor will not connect at all.
- SSH access with `sudo`.
- Rust on the box (`rustup`), **and a C toolchain** — `rustc` shells out to
  `cc` as its linker driver, and Ubuntu Minimal images ship without one:
  `sudo apt install -y build-essential`. No dependency compiles C code; this
  is only needed for the final link.
- Node on your **local** machine. The box never needs Node — the frontend is
  built locally and shipped as static files.

The deploy script checks both before shipping anything, because otherwise a
missing linker surfaces at the end of a build that takes 10-20 minutes on a
small instance.

## The one command

```sh
RUNA_HOST=runa.example.com RUNA_BOX_IP=203.0.113.10 ./scripts/deploy-oracle.sh
```

`RUNA_HOST` and `RUNA_BOX_IP` are **required** — there is deliberately no
default, because the obvious default is whatever host you set up first, and
deploying onto the wrong machine is not an error you want to make quietly.

Re-run it to ship an update; it is idempotent. Other knobs:

| Variable | Default | |
|---|---|---|
| `RUNA_SSH_USER` | `ubuntu` | |
| `RUNA_SSH_KEY` | `~/.ssh/id_ed25519` | |
| `RUNA_MEM_MAX` / `RUNA_MEM_HIGH` | `2G` / `1700M` | cgroup caps |
| `RUNA_LOG_MB` | `700` | retained ciphertext, all rooms |
| `RUNA_ROOMS` / `RUNA_PEERS` | `512` / `32` | |
| `RUNA_CONNS` / `RUNA_QUEUE_KB` | `512` / `1024` | |
| `RUNA_NEIGHBOUR_URL` | *(unset)* | a service to health-check afterwards |
| `RUNA_SKIP_WEB_BUILD` | `0` | `1` ships the `web/dist` you already built instead of rebuilding it |
| `RUNA_ONION` | `0` | `1` also serves RÚNA as a Tor onion service — see [Onion service](#onion-service) |

The memory knobs move together: the script writes the `RUNA_MAX_*` values
into `/etc/runa/runa.env` and patches `MemoryMax`/`MemoryHigh` in the unit
from the same invocation, so the cgroup cap and the application ceilings
cannot drift apart.

It refuses to run on a dirty working tree. `git archive` ships the committed
tree, so uncommitted work would be silently left behind — the script makes
that a hard error rather than a surprise in production.

### What it does

| Step | |
|---|---|
| 1 | Preflight: ssh reachable, tree clean, DNS resolves to the box **unproxied** |
| 2 | `npm ci && npm run build` locally |
| 3 | Bundle digest, computed the way `release.yml` computes it |
| 4 | `git archive` the commit; tar the bundle; `scp` both |
| 5 | Build on the box with `--locked`, niced, stamping commit + digest into the binary |
| 6 | Install binary, swap assets atomically, install unit, restart |
| 7 | Append the Caddy vhost behind backup → validate → rollback-on-failure; if Caddy comes from its official apt repository, add that origin to unattended-upgrades (`/etc/apt/apt.conf.d/52runa-caddy`) |
| 8 | Verify: loopback bind, HTTPS 200, `/version` matches, no client IPs in logs, other sites still healthy |

Step 7 never edits another site's configuration. It backs the file up,
appends, validates, and restores the backup if validation fails — a broken
Caddyfile would take TLS down for every site on the box.

## Sizing

`deploy/runa.env` carries the limits; `deploy/runa.service` carries
`MemoryMax`. **They must move together.** Rooms live only in RAM, so the
worst case is whatever you configure:

```
peak ≈ 25 MB baseline
     + 1.4 × RUNA_MAX_TOTAL_LOG_MB      (entry records + allocator slack)
     + RUNA_MAX_CONNECTIONS × RUNA_MAX_QUEUE_KB
     + ~32 MB rate-limiter tables, fully saturated
```

The shipped values — 700 MB of history, 512 concurrent editors — work out to
about 1549 MB, under a `MemoryMax=2G` cap with roughly 500 MB of headroom.
`MemoryHigh=1700M` makes the kernel reclaim and throttle before the cap kills
anything, which matters: a throttled RÚNA recovers, a killed one has
destroyed every live document.

To resize, edit `/etc/runa/runa.env` and `MemoryMax` in the unit, then
`sudo systemctl restart runa`. A redeploy will not overwrite `runa.env` once
it exists.

Two variables must stay unset in production:

- `RUNA_ALLOW_INSECURE` — permits plain `ws://`.
- `RUNA_ALLOW_CEILING_OPTOUT` — lets any anonymous caller create a room that
  never expires, which is a permanent memory reservation.

## Onion service

```sh
RUNA_ONION=1 RUNA_HOST=runa.example.com RUNA_BOX_IP=203.0.113.10 ./scripts/deploy-oracle.sh
```

Someone who opens RÚNA through its onion address never gives it an IP
address: the server sees only the local Tor daemon, and their network sees
only that they use Tor. For anyone who could be harmed by being linked to a
room, that is the strongest protection RÚNA offers.

What the option does, and nothing else:

- Installs or upgrades `tor` from the Tor Project's own repository rather than
  Ubuntu's, whose copy sits in universe and gets no routine security updates.
  It fetches the repository's signing key, refuses it unless the fingerprint is
  `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`, and writes three files:
  `/usr/share/keyrings/deb.torproject.org-keyring.gpg`,
  `/etc/apt/sources.list.d/tor.sources`, and
  `/etc/apt/apt.conf.d/52runa-torproject`, which lets unattended-upgrades
  apply Tor's releases the way it applies Ubuntu's.
- Adds one file to tor, `/etc/tor/torrc.d/runa.conf`, plus an `%include` line
  in `/etc/tor/torrc`, which upgrades keep. Caddy, its vhosts and every other
  service on the box are untouched.
- `HiddenServiceExportCircuitID haproxy` makes tor open each connection with
  a line naming its circuit. RÚNA's onion listener (`RUNA_ONION_BIND`,
  loopback only) treats each circuit as its own client, so one Tor visitor
  cannot spend everyone else's limits, and believes no `X-Forwarded-For`, so
  none can forge a fresh allowance.
- `HiddenServicePoWDefensesEnabled 1` makes opening circuits in bulk costly,
  since each circuit is a fresh allowance. If the box's tor build lacks it,
  the deploy says so and carries on without it.
- `RUNA_ONION_URL` makes the clearnet pages send `Onion-Location`, so Tor
  Browser offers the onion address on its own.

The onion address lives in `/var/lib/tor/runa/`. **Back that directory up**
if the address is published anywhere — losing it means a new address. It is
tor's private key, so keep the backup as carefully as the box itself.

The onion service is for the systemd path; the Docker path does not set it up.

## After it is live

```sh
# Did a limit bind?
sudo journalctl -u runa | grep -E 'room budget exhausted|connection ceiling'

# Is the served bundle the one you built?
curl -s https://runa.example.com/version
```

- **A planned restart hands rooms over; a crash does not.** On `systemctl
  restart` (and every redeploy) the stopping process gives each connected
  member a ticket signed with `RUNA_RESTART_KEY`, and their pages rebuild the
  room on the new process. The key lives in `/etc/runa/restart.env` (root,
  0600), written once by the deploy script. Do not rotate it casually: tickets
  signed under the old key cannot be read under a new one, so the restart that
  changes it ends every open room. A crash skips the handover, so
  `Restart=on-failure` brings the service back without them — a non-zero
  restart count in `systemctl status runa` is worth investigating.
- **The first deploy that brings the handover restarts the old binary**, which
  has never heard of tickets, so that one restart still ends open rooms. Every
  restart after it carries them over.
- **Check it is on** with `sudo journalctl -u runa | grep 'restart key'`: the
  process says at startup whether it will hand rooms over.
- **Reboots destroy rooms.** Kernel updates included. Schedule them, and tell
  whoever is using it.
- **Rooms are not backed up, ever.** That is the product, not an omission.

## Backing out

```sh
./scripts/rollback-oracle.sh          # stop the service, leave Caddy alone
./scripts/rollback-oracle.sh --full   # also remove the Caddy vhost
```

The `--full` form removes exactly the RÚNA vhost block, validates, and
restores its backup if validation fails. Other sites are untouched.
