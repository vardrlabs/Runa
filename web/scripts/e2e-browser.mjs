import { spawn } from "node:child_process";
import { webcrypto as crypto } from "node:crypto";
import { createHash, randomBytes } from "node:crypto";
import { chromium, firefox, webkit } from "playwright";

/// Which engine this run drives. Chromium by default so a bare `npm run smoke`
/// behaves as it always did; CI runs all three.
///
/// Two of the faults that reached real users could not have been caught here
/// on one engine. The line-ending corruption needed a client whose Monaco
/// model used CRLF, which no headless Chromium on macOS produces, so peers
/// agreed in CI and diverged in the field. The <select> overflow in #13 is
/// documented as unreproducible in Chromium at all, headless or emulated.
const ENGINES = { chromium, firefox, webkit };
const ENGINE_NAME = process.env.RUNA_E2E_BROWSER ?? "chromium";
const ENGINE = ENGINES[ENGINE_NAME];
if (!ENGINE) {
  throw new Error(`unknown RUNA_E2E_BROWSER "${ENGINE_NAME}"; expected one of ${Object.keys(ENGINES).join(", ")}`);
}

const BASE = "http://127.0.0.1:3001";
const errors = [];
let alicePage = null;
let bobPage = null;
let serverLogRef = null;
const enc = new TextEncoder();
const INFO_AUTH = enc.encode("runa/v1/auth");
const INFO_CONTENT = enc.encode("runa/v1/content");

const b64 = (b) => Buffer.from(b).toString("base64");

async function hkdf(ikm, salt, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

function waitForProcessExit(proc) {
  return new Promise((resolve) => proc.once("exit", resolve));
}

/// Open a page of the app — the front page or a room — recovering from a
/// Playwright bug that strands Firefox navigations.
///
/// On the Linux runner Firefox timed out opening a room page on four runs, at
/// three different pages, and waiting only for commit instead of
/// DOMContentLoaded changed nothing. When the stalled page could be asked, it
/// had loaded perfectly — the room rendered, nothing in flight — while
/// Playwright still reported about:blank.
///
/// That is microsoft/playwright#42183. In Firefox a small share of navigations
/// in a fresh context never settle although the page is complete, and every
/// locator after one hangs as well, so carrying on is not an option. It is
/// closed upstream without a fix, and nothing in 1.63 addresses it. Its
/// reporter, and a second project that shipped the same workaround, found that
/// a superseding navigation releases it.
///
/// Recovery arms only on that exact signature, and only in Firefox: five
/// seconds in, the page still answers, is at the requested URL and reports a
/// complete document. "The requested URL" ignores the fragment, because the
/// app takes the key out of the address bar as it starts (keyhandoff.ts): a
/// room page that loaded correctly is at `/r/<id>`, never `/r/<id>#k=…`. Anything else keeps the original navigation
/// and its verdict. Every recovery is written to the log, and the room still
/// has to come up — each caller waits for the editor next.
///
/// The front page goes through here too. Two Firefox runs on 2026-10-07 timed
/// out on its very first load, waiting for DOMContentLoaded, with the server
/// up — the same stranding, at a load that had no recovery.
///
/// Request listeners were taken off these pages once the diagnosis was done:
/// listeners attached before navigating are one of the conditions the upstream
/// issue needs in order to reproduce.
async function gotoPage(page, label, url) {
  const nav = page.goto(url, { waitUntil: "commit" });
  nav.catch(() => {});
  const early = await Promise.race([
    nav.then(
      () => "ok",
      (e) => e,
    ),
    new Promise((r) => setTimeout(() => r("slow"), 5000)),
  ]);
  if (early === "ok") return;
  if (early !== "slow") throw new Error(`[${label}] ${String(early.message).split("\n")[0]}`);

  const probe = ENGINE_NAME === "firefox" ? await probeDocument(page) : null;
  if (!probe || withoutFragment(probe.href) !== withoutFragment(url) || probe.ready !== "complete") {
    try {
      await nav;
      return;
    } catch (e) {
      throw new Error(`[${label}] ${String(e.message).split("\n")[0]}; page reported ${JSON.stringify(probe)}`);
    }
  }
  await releaseStuckNavigation(page, label, url);
}

function withoutFragment(href) {
  return typeof href === "string" ? href.split("#")[0] : href;
}

async function probeDocument(page) {
  return Promise.race([
    page
      .evaluate(() => ({ href: location.href, ready: document.readyState }))
      .catch((err) => ({ error: String(err.message).split("\n")[0] })),
    new Promise((r) => setTimeout(() => r({ error: "no answer within 3s" }), 3000)),
  ]);
}

const INFO_CONTENT_E2E = INFO_CONTENT;

/// Wait until a page's preview contains `needle`.
async function waitForPreview(page, needle, label, ms = 30_000) {
  const until = Date.now() + ms;
  for (;;) {
    const text = await page.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
    if (text.includes(needle)) return;
    if (Date.now() > until) throw new Error(`[${label}] never showed "${needle}"; preview: "${text.slice(0, 200)}"`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

/// A peer that is not a browser: it joins with the link's key the way a
/// departed member who kept the link would, and can fetch the room's log and
/// try to open each entry with the epoch-0 key (PROTOCOL amendment J).
async function rawPeer(roomIdHex, linkKey, linkSalt) {
  const authKey = await hkdf(linkKey, linkSalt, INFO_AUTH, 32);
  const contentRaw = await hkdf(linkKey, linkSalt, INFO_CONTENT_E2E, 32);
  const content0 = await crypto.subtle.importKey("raw", contentRaw, { name: "AES-GCM" }, false, ["decrypt"]);
  const roomId = Buffer.from(roomIdHex, "hex");
  const ws = new WebSocket(`${BASE.replace("http", "ws")}/socket/${roomIdHex}`);
  ws.binaryType = "arraybuffer";
  const frames = [];
  let onFrame = null;
  ws.onmessage = (ev) => {
    const b = new Uint8Array(ev.data);
    frames.push(b);
    onFrame?.(b);
  };
  const header = (ft) => {
    const h = new Uint8Array(32);
    h.set([0x52, 0x55, 0x01, ft]);
    h.set(roomId, 4);
    return h;
  };
  const send = (ft, obj) => ws.send(Buffer.concat([header(ft), Buffer.from(JSON.stringify(obj))]));
  const joined = new Promise((resolve, reject) => {
    ws.onopen = () =>
      send(0x01, { auth_key: b64(authKey), pubkey: b64(crypto.getRandomValues(new Uint8Array(32))), client_version: "e2e-raw" });
    onFrame = (b) => {
      if (b[3] === 0x02) resolve();
      if (b[3] === 0x30) reject(new Error(`raw peer refused: ${Buffer.from(b.slice(32)).toString()}`));
    };
    ws.onerror = () => reject(new Error("raw peer socket error"));
    setTimeout(() => reject(new Error("raw peer join timed out")), 10_000);
  });
  return {
    joined,
    content0,
    close: () => ws.close(),
    async syncAll() {
      const start = frames.length;
      send(0x04, { from_index: 0 });
      await new Promise((r) => setTimeout(r, 2_000));
      return frames
        .slice(start)
        .filter((b) => b[3] === 0x03 || b[3] === 0x21)
        .map((b) => ({
          epoch: new DataView(b.buffer, b.byteOffset).getUint32(20, false),
          async openWith(key) {
            const head = b.slice(0, 32);
            const sender = b.slice(32, 48);
            let body = b.slice(48);
            let covers = new Uint8Array(8);
            if (b[3] === 0x21) {
              covers = body.slice(0, 8);
              body = body.slice(8);
            }
            const counter = body.slice(4, 12);
            const iv = Buffer.concat([body.slice(0, 4), counter]);
            const aad = Buffer.concat([Buffer.from("runa/v1"), head, sender, counter, covers]);
            try {
              await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, body.slice(12));
              return true;
            } catch {
              return false;
            }
          },
        }));
    },
  };
}

/// Supersede a stranded navigation with a full round trip: leave the page, then
/// load the room again.
///
/// Both upstream reports released it with a second navigation to the same URL,
/// but their URLs had no fragment. Ours do, and navigating to the URL a document
/// already has is only a jump within it. Forcing this recovery on healthy room
/// pages showed exactly that: the same-URL attempt settled in under 15ms and
/// never created a new document. Nothing says a jump releases a stranded
/// navigation, and if it did not, goto would return and the next locator would
/// hang instead. Going through about:blank makes both navigations real loads,
/// which is the case the reports actually cover.
async function releaseStuckNavigation(page, label, url) {
  console.log(
    `  note: [${label}] Firefox navigation stranded with the page complete; superseding it with a reload (microsoft/playwright#42183)`,
  );
  try {
    await page.goto("about:blank", { timeout: 10_000 });
    await page.goto(url, { waitUntil: "commit", timeout: 10_000 });
  } catch (e) {
    throw new Error(`[${label}] a stranded navigation could not be released: ${String(e.message).split("\n")[0]}`);
  }
}

/// Both processes in the restart test must hold the same key, or the second
/// could not open the tickets the first hands out.
const RESTART_KEY = "ab".repeat(32);

const serverLog = [];
const servers = [];

async function startServer() {
  const proc = spawn(`${process.cwd()}/../target/release/runa-server`, [], {
    env: {
      ...process.env,
      RUNA_DIST: "dist",
      RUNA_BIND: "127.0.0.1:3001",
      RUNA_SHUTDOWN_GRACE_SECS: "5",
      RUNA_RESTART_KEY: RESTART_KEY,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  proc.stdout.on("data", (d) => serverLog.push(d.toString()));
  proc.stderr.on("data", (d) => serverLog.push(d.toString()));
  servers.push(proc);
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start")), 5000);
    const poll = setInterval(async () => {
      try { await fetch(`${BASE}/version`); clearInterval(poll); clearTimeout(t); resolve(); } catch {}
    }, 150);
  });
  return proc;
}

async function main() {
  serverLogRef = serverLog;
  const killServer = () => { for (const p of servers) { try { p.kill(); } catch {} } };
  process.on("exit", killServer);
  process.on("uncaughtException", (e) => { console.error("UNCAUGHT:", e); killServer(); process.exit(1); });
  const server = await startServer();

  // Create an unlisted room with keys the pages will receive via fragment.
  const linkSecret = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const authKey = await hkdf(linkSecret, salt, INFO_AUTH, 32);
  const verifier = createHash("sha256").update(authKey).digest().toString("base64");
  const createRes = await fetch(`${BASE}/api/rooms/unlisted`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      verifier,
      kdf: { m_kib: 65536, t: 3, p: 1, salt: b64(salt) },
      ttl: { kind: "idle-peers", secs: 3600 },
    }),
  });
  if (createRes.status !== 201) throw new Error(`create failed ${createRes.status}`);
  // The server assigns the id.
  const roomIdHex = (await createRes.json()).room_id;

  const b64url = (b) => Buffer.from(b).toString("base64url");
  const roomUrl = `${BASE}/r/${roomIdHex}#k=${b64url(linkSecret)}&s=${b64url(salt)}`;

  const browser = await ENGINE.launch();

  async function makePage(label) {
    const page = await browser.newPage();
    // Keep a handle on every WebSocket the page opens, so a test can sever one.
    // See severNetwork() for why the tests do not use setOffline for this.
    await page.addInitScript(() => {
      const Original = WebSocket;
      const opened = [];
      window.__runaSockets = opened;
      const Patched = function (...args) {
        const ws = new Original(...args);
        opened.push(ws);
        // Severed: refuse the connection. Closing while still CONNECTING means
        // onopen can never fire, so nothing reaches the server, and the client
        // gets the close event after it has attached its handlers — the same
        // thing it sees when the network is really gone.
        // Two more ways a network fails, for the tests that need them. A
        // connection that has died without the browser noticing stays OPEN:
        // what it sends vanishes and nothing arrives. And a slow round trip
        // delivers JOIN_ACK late, leaving the socket open before the join is
        // confirmed. Each socket takes its delay from when it was made, and a
        // test can lift it afterwards.
        const realSend = ws.send.bind(ws);
        ws.send = (data) => {
          if (!ws.__runaDead) realSend(data);
        };
        ws.__runaDelayMs = window.__runaDelayInboundMs || 0;
        let handler = null;
        Object.defineProperty(ws, "onmessage", {
          configurable: true,
          get: () => handler,
          set: (h) => {
            handler = h;
          },
        });
        ws.addEventListener("message", (ev) => {
          if (ws.__runaDead) return;
          const run = () => {
            if (ws.__runaFirstDeliveredAt === undefined) ws.__runaFirstDeliveredAt = Date.now();
            handler?.call(ws, ev);
          };
          if (ws.__runaDelayMs > 0) setTimeout(run, ws.__runaDelayMs);
          else run();
        });
        if (window.__runaSevered) ws.close();
        return ws;
      };
      Patched.prototype = Original.prototype;
      Object.assign(Patched, Original);
      window.WebSocket = Patched;
    });
    page.on("console", (msg) => {
      const t = msg.type();
      if (t === "error") errors.push(`[${label}] console.error: ${msg.text()}`);
    });
    page.on("pageerror", (err) => errors.push(`[${label}] pageerror: ${err.message}`));
    return page;
  }

  /// Take one page's network away, the same way on every engine.
  ///
  /// `context.setOffline` is not that. Running the suite on three engines was
  /// what showed how far apart they are: all three refuse new *HTTP* requests
  /// while offline, but only Chromium tears down an established WebSocket —
  /// Gecko leaves it up, and WebKit will happily open a brand new one while
  /// `navigator.onLine` is false. The offline peer there reconnected inside
  /// the same tick, stayed in sync, and the split-brain test then failed its
  /// own precondition rather than passing on a setup that never happened.
  ///
  /// So do neither engine's version of offline. From inside the page, close
  /// the socket that is up and refuse every new one until restored — the
  /// patched constructor in makePage does the refusing. The client sees a
  /// close it did not ask for and retries on its backoff, which is what a lost
  /// network actually looks like.
  ///
  /// Not `page.routeWebSocket`, which was the first version of this. It relays
  /// every frame of every routed socket through the Playwright driver, so the
  /// sync tests were measuring traffic that took a detour through the test
  /// harness rather than the connection they claim to test — and on the Linux
  /// runner Firefox then hung loading the second peer while the first one's
  /// frames were being relayed. Cause not proven; the detour is wrong anyway.
  async function severNetwork(page) {
    await page.evaluate(() => {
      window.__runaSevered = true;
      for (const ws of window.__runaSockets ?? []) {
        try {
          ws.close();
        } catch {
          /* already closed */
        }
      }
    });
    await page.waitForTimeout(300);
  }

  /// Give it back. The next backoff attempt connects for real.
  async function restoreNetwork(page) {
    await page.evaluate(() => {
      window.__runaSevered = false;
    });
  }

  // Guards against horizontal scroll on the landing page at phone widths.
  //
  // Scope, honestly: this catches fixed widths, wide tables and unbreakable
  // strings. It does NOT catch the bug that prompted it. On iOS Safari a
  // <select> grows to fit its longest <option> and drags the page sideways;
  // Chromium clamps it — headless and under device emulation alike — so the
  // failure is unreproducible here. Measured: the same page that scrolled
  // 214px sideways on a real iPhone reports zero overflow in this engine.
  //
  // The CSS fix (width:100% on form controls) is correct by construction
  // rather than by this test. Left in place because the class of bug is
  // common and the check is nearly free.
  // Someone sent a link and you are on the front page: paste it into Join. It
  // has to arrive with its key, since the key is the part after the # and a
  // join box that dropped it would open onto "this link is missing its key".
  const joiner = await makePage("join");
  await gotoPage(joiner, "joiner", `${BASE}/`);
  await joiner.waitForSelector("#join-room", { timeout: 10_000 });
  await joiner.fill("#join-room", `  ${roomUrl}  `);
  await joiner.press("#join-room", "Enter");
  await joiner.waitForSelector(".monaco-editor", { timeout: 30_000 }).catch(async () => {
    const shown = await joiner.evaluate(() => document.body.textContent.replace(/\s+/g, " ").slice(0, 200));
    throw new Error(`[join] pasting a room link into Join did not open the room: ${shown}`);
  });
  // The key is handed over in memory: the room opens, and nothing the
  // browser could write into its history carries the key.
  if (await joiner.evaluate(() => location.href.includes("#k="))) {
    throw new Error("[join] the key reached the address bar, and with it the browser's history");
  }
  await joiner.close();

  // A clicked link brings its key in the address; the page takes it out
  // before anything else runs.
  {
    const clicked = await makePage("clicked-link");
    await gotoPage(clicked, "clicked-link", roomUrl);
    await clicked.waitForSelector(".monaco-editor", { timeout: 30_000 });
    const href = await clicked.evaluate(() => location.href);
    if (href.includes("#k=")) throw new Error(`[clicked-link] the key stayed in the address: ${href}`);
    await clicked.close();
  }

  // Highest security, end to end, as its creator and a recipient meet it.
  {
    const maker = await makePage("highest");
    await maker.addInitScript(() => {
      window.__copied = [];
      const write = (t) => { window.__copied.push(t); return Promise.resolve(); };
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: write } });
    });
    await gotoPage(maker, "maker", `${BASE}/`);
    await maker.waitForSelector("#security", { timeout: 10_000 });
    await maker.selectOption("#security", "highest");
    await maker.click('button:has-text("Create private room")');
    await maker.waitForSelector(".statusbar", { timeout: 30_000 });
    if (await maker.evaluate(() => location.href.includes("#k="))) {
      throw new Error("[highest] creating a room put its key in the address");
    }
    await maker.waitForSelector('text=Highest security: this tab holds the key in memory only', { timeout: 10_000 });
    if (await maker.evaluate(() => history.state !== null)) {
      throw new Error("[highest] the key was saved into the tab's state");
    }
    await maker.click('.statusbar-actions button:has-text("Copy link")');
    const link = await maker.evaluate(() => window.__copied.at(-1));
    if (!link || !/\/r\/[0-9a-f]{32}#k=[^&]+&s=/.test(link)) {
      throw new Error(`[highest] Copy link did not produce a whole link: ${link}`);
    }

    // Refresh: the tab has forgotten the key, on purpose.
    await maker.reload({ waitUntil: "domcontentloaded" });
    await maker.waitForSelector("text=THIS LINK IS MISSING ITS KEY", { timeout: 10_000 }).catch(async () => {
      const shown = await maker.evaluate(() => document.body.textContent.replace(/\s+/g, " ").slice(0, 200));
      throw new Error(`[highest] a refresh still had the key: ${shown}`);
    });
    await maker.close();

    // The copied link still opens the room for whoever receives it.
    const recipient = await makePage("highest-recipient");
    await gotoPage(recipient, "highest-recipient", link);
    await recipient.waitForSelector(".monaco-editor", { timeout: 30_000 });
    if (await recipient.evaluate(() => location.href.includes("#k="))) {
      throw new Error("[highest] the recipient's address kept the key");
    }
    await recipient.close();
  }

  // Key rotation (PROTOCOL amendment J). Three peers in a Highest room; one
  // leaves. Sixty seconds later the room's key changes, the departed peer's
  // epoch-0 key no longer opens anything written afterwards, and a newcomer is
  // handed the keys and reads the whole history.
  {
    const a = await makePage("rotation-a");
    await a.addInitScript(() => {
      window.__copied = [];
      const write = (t) => {
        window.__copied.push(t);
        return Promise.resolve();
      };
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: write } });
    });
    await gotoPage(a, "rotation-a", `${BASE}/`);
    await a.waitForSelector("#security", { timeout: 10_000 });
    await a.selectOption("#security", "highest");
    await a.click('button:has-text("Create private room")');
    await a.waitForSelector(".monaco-editor", { timeout: 30_000 });
    await a.click('.statusbar-actions button:has-text("Copy link")');
    const link = await a.evaluate(() => window.__copied.at(-1));
    const m = /\/r\/([0-9a-f]{32})#k=([^&]+)&s=(.+)$/.exec(link ?? "");
    if (!m) throw new Error(`[rotation] Copy link gave no whole link: ${link}`);
    const [, rid, k64, s64] = m;
    const linkKey = Buffer.from(k64, "base64url");
    const linkSalt = Buffer.from(s64, "base64url");

    await a.waitForSelector("textarea.inputarea", { state: "attached", timeout: 15_000 });
    await a.click(".monaco-editor .view-lines");
    await a.keyboard.type("before-rotation ");

    const b = await makePage("rotation-b");
    await gotoPage(b, "rotation-b", link);
    await b.waitForSelector(".monaco-editor", { timeout: 30_000 });
    await waitForPreview(b, "before-rotation", "rotation-b");

    // The third peer joins, proves its epoch-0 key opens the log, and leaves.
    const departed = await rawPeer(rid, linkKey, linkSalt);
    await departed.joined;
    const early = await departed.syncAll();
    const opensEarly = (await Promise.all(early.map((e) => e.openWith(departed.content0)))).some(Boolean);
    if (!opensEarly) throw new Error("[rotation] the departed peer's key opened nothing even before it left; the check below would prove nothing");
    departed.close();

    // 60 s of grace, then the longest-connected member steps.
    await new Promise((r) => setTimeout(r, 65_000));
    await a.click(".monaco-editor .view-lines");
    await a.keyboard.press("End");
    await a.keyboard.type("after-rotation ");
    await waitForPreview(b, "after-rotation", "rotation-b");

    const spy = await rawPeer(rid, linkKey, linkSalt);
    await spy.joined;
    const entries = await spy.syncAll();
    spy.close();
    if (!entries.some((e) => e.epoch >= 1)) {
      throw new Error(`[rotation] no entry from after the rotation; epochs seen: ${[...new Set(entries.map((e) => e.epoch))]}`);
    }
    for (const e of entries) {
      if (e.epoch >= 1 && (await e.openWith(departed.content0))) {
        throw new Error(`[rotation] the departed peer's key opened an entry from epoch ${e.epoch}`);
      }
    }

    for (const [label, page] of [["rotation-a", a], ["rotation-b", b]]) {
      const alarms = await page.$$eval('.banner[role="alert"]', (els) => els.map((e) => e.textContent));
      if (alarms.some((t) => /key change|list of people|lost track/.test(t))) {
        throw new Error(`[${label}] showed a key alarm after an honest rotation: ${alarms.join(" | ")}`);
      }
    }

    const c = await makePage("rotation-c");
    await gotoPage(c, "rotation-c", link);
    await c.waitForSelector(".monaco-editor", { timeout: 30_000 });
    await waitForPreview(c, "before-rotation", "rotation-c", 45_000);
    await waitForPreview(c, "after-rotation", "rotation-c");
    for (const p of [a, b, c]) await p.close();
  }

  const landing = await makePage("landing");
  for (const width of [320, 375, 414]) {
    await landing.setViewportSize({ width, height: 780 });
    await gotoPage(landing, "landing", `${BASE}/`);
    await landing.waitForSelector(".landing", { timeout: 5000 });
    const m = await landing.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      const offenders = [];
      for (const el of document.querySelectorAll("*")) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.right > vw + 1) {
          offenders.push(`${el.tagName.toLowerCase()}.${String(el.className || "").split(" ")[0]}=${Math.round(r.right)}px`);
        }
      }
      return { vw, scrollW: document.documentElement.scrollWidth, offenders: offenders.slice(0, 5) };
    });
    if (m.scrollW > m.vw + 1) {
      throw new Error(
        `[landing] scrolls sideways at ${width}px (content ${m.scrollW}px): ${m.offenders.join(", ")}`,
      );
    }
  }
  // Vertical companion to the check above, and a different failure entirely:
  // content stranded ABOVE the scroll origin, which no scrolling can reach
  // because scrollTop stops at 0. .landing centres itself with
  // justify-content:center inside #root, which is `height: 100%` — so once
  // the named-room form expands past the viewport, .landing is a flex item
  // with negative free space, gets shrunk, and min-height:100dvh clamps it at
  // exactly one viewport while its content is taller. Centring then splits
  // that overflow evenly top and bottom. On a phone it reads as "scrolls down
  // but not up", with the masthead sliced through by the top of the screen.
  //
  // Unlike the sideways guard above, this one DOES reproduce in Chromium:
  // verified by reverting the fix, which puts .masthead at -90px at 375x812.
  // This check is load-bearing, not decorative — it is checked in the
  // expanded state on purpose, because the default state never overflows and
  // measuring only that is what let the bug through.
  for (const [width, height] of [[320, 568], [375, 667], [375, 812], [414, 896]]) {
    await landing.setViewportSize({ width, height });
    await gotoPage(landing, "landing", `${BASE}/`);
    await landing.waitForSelector(".landing", { timeout: 5000 });
    await landing.click("text=Shared name");
    await landing.waitForSelector("text=Create shared room", { timeout: 5000 });
    const stranded = await landing.evaluate(() => {
      document.scrollingElement.scrollTop = 0;
      const above = [];
      for (const el of document.querySelectorAll(".landing, .landing *")) {
        const r = el.getBoundingClientRect();
        const cls = String(el.className || "").split(" ")[0];
        if (r.height > 0 && cls !== "ambient-field" && r.top < -1) {
          above.push(`${el.tagName.toLowerCase()}.${cls}@${Math.round(r.top)}px`);
        }
      }
      return above.slice(0, 5);
    });
    if (stranded.length > 0) {
      throw new Error(
        `[landing] named-room form strands content above the scroll origin at ${width}x${height}: ${stranded.join(", ")}`,
      );
    }
  }

  // A name that is already taken has to say so, and say it before the key
  // derivation runs. Creation used to check the name only after Argon2 had
  // spent seconds deriving keys, and then answered with a message about the
  // passphrase; on a device where Argon2 failed, all anyone saw was a red
  // banner about a weaker key derivation. Two pages, one name.
  {
    const takenName = `e2e-taken-${Math.random().toString(16).slice(2, 8)}`;
    const createNamed = async (page) => {
      await page.setViewportSize({ width: 1280, height: 900 });
      await gotoPage(page, "page", `${BASE}/`);
      await page.waitForSelector(".landing", { timeout: 5000 });
      await page.click("text=Shared name");
      await page.waitForSelector("text=Create shared room", { timeout: 5000 });
      const suffix = page.locator(".checkbox-row input[type=checkbox]");
      if (await suffix.isChecked()) await suffix.uncheck();
      await page.fill("#room-name", takenName);
      await page.click('button:has-text("Generate")');
      const passphrase = await page.inputValue("#passphrase");
      await page.click('button:has-text("Create shared room")');
      return passphrase;
    };

    // The first creation is also the check that Argon2id runs at all under the
    // policy this server sends. Without 'wasm-unsafe-eval' every engine refused
    // to compile it, and the client fell back to PBKDF2 without a word.
    const first = await makePage("named-first");
    const passphrase = await createNamed(first);
    try {
      await first.waitForURL(`${BASE}/${takenName}`, { timeout: 60_000 });
    } catch {
      const shown = await first.evaluate(() =>
        [...document.querySelectorAll(".error-text")].map((e) => e.textContent.trim()).join(" | "),
      );
      throw new Error(`[named] creating a named room never left the form; the page shows: ${shown || "nothing"}`);
    }

    const second = await makePage("named-second");
    await createNamed(second);
    let refusal;
    try {
      refusal = await second.waitForSelector('[role="alert"]:has-text("already taken")', { timeout: 5000 });
    } catch {
      const shown = await second.evaluate(() =>
        [...document.querySelectorAll(".error-text")].map((e) => e.textContent.trim()).join(" | "),
      );
      throw new Error(`[named] a taken name was not refused as taken within 5s; the page shows: ${shown || "nothing"}`);
    }
    const said = (await refusal.textContent()) ?? "";
    if (!said.includes(takenName)) {
      throw new Error(`[named] the refusal does not say which name is taken: ${said}`);
    }
    if (new URL(second.url()).pathname !== "/") {
      throw new Error(`[named] the second page left the form anyway: ${second.url()}`);
    }
    // And the room has to open in another page with the passphrase it was
    // made with. The fallback's other half was a room created with one
    // derivation and joined with another, which looked like a wrong
    // passphrase; this is the check that Argon2id runs on the joining side too.
    const joiner = await makePage("named-joiner");
    await gotoPage(joiner, "joiner", `${BASE}/${takenName}`);
    await joiner.waitForSelector("#pp", { timeout: 15_000 });
    await joiner.fill("#pp", passphrase);
    await joiner.click('button:has-text("Enter room")');
    try {
      await joiner.waitForSelector(".monaco-editor", { timeout: 60_000 });
    } catch {
      const shown = await joiner.evaluate(() => (document.querySelector("main")?.textContent ?? "").trim().slice(0, 200));
      throw new Error(`[named] the room did not open with its own passphrase; the page shows: ${shown || "nothing"}`);
    }
    await joiner.close();

    // An everyday shared room opened from Join gets its usual address once
    // the room has said it is everyday, so it can be refreshed and shared.
    const viaJoin = await makePage("named-via-join");
    await gotoPage(viaJoin, "viaJoin", `${BASE}/`);
    await viaJoin.waitForSelector("#join-room", { timeout: 10_000 });
    await viaJoin.fill("#join-room", takenName);
    await viaJoin.press("#join-room", "Enter");
    await viaJoin.waitForSelector("#pp", { timeout: 15_000 });
    await viaJoin.fill("#pp", passphrase);
    await viaJoin.click('button:has-text("Enter room")');
    await viaJoin.waitForSelector(".monaco-editor", { timeout: 60_000 });
    await viaJoin.waitForFunction((n) => location.pathname === `/${n}`, takenName, { timeout: 10_000 }).catch(async () => {
      throw new Error(`[named] an everyday room opened from Join never took its address: ${await viaJoin.evaluate(() => location.pathname)}`);
    });
    await viaJoin.close();
    await first.close();
    await second.close();
  }

  // A highest-security shared room: its name never reaches the address bar,
  // so nothing in the browser's history says which room this was.
  {
    const secretName = `e2e-quiet-${randomBytes(3).toString("hex")}`;
    const maker = await makePage("named-highest");
    await maker.setViewportSize({ width: 1280, height: 900 });
    await gotoPage(maker, "maker", `${BASE}/`);
    await maker.click("text=Shared name");
    await maker.waitForSelector("text=Create shared room", { timeout: 5000 });
    const suffix = maker.locator(".checkbox-row input[type=checkbox]");
    if (await suffix.isChecked()) await suffix.uncheck();
    await maker.fill("#room-name", secretName);
    await maker.selectOption("#security", "highest");
    if ((await maker.getAttribute("#passphrase", "autocomplete")) !== "off") {
      throw new Error("[named-highest] the passphrase field still invites the browser to save it");
    }
    await maker.click('button:has-text("Generate")');
    const phrase = await maker.inputValue("#passphrase");
    await maker.click('button:has-text("Create shared room")');
    await maker.waitForSelector("#pp", { timeout: 60_000 });
    const enter = async (page) => {
      await page.fill("#pp", phrase);
      await page.click('button:has-text("Enter room")');
      await page.waitForSelector(".monaco-editor", { timeout: 60_000 });
      await page.waitForSelector("text=Highest security: this room's name stays out", { timeout: 10_000 });
      const href = await page.evaluate(() => location.href);
      if (href.includes(secretName) || new URL(href).pathname !== "/") {
        throw new Error(`[named-highest] the room's name reached the address: ${href}`);
      }
    };
    await enter(maker);
    // A refresh leaves the room, by design: nothing on the device remembers it.
    await maker.reload({ waitUntil: "domcontentloaded" });
    await maker.waitForSelector(".landing", { timeout: 10_000 }).catch(() => {
      throw new Error("[named-highest] a refresh did not leave the room");
    });
    await maker.close();

    const guest = await makePage("named-highest-join");
    await gotoPage(guest, "guest", `${BASE}/`);
    await guest.waitForSelector("#join-room", { timeout: 10_000 });
    await guest.fill("#join-room", secretName);
    await guest.press("#join-room", "Enter");
    await guest.waitForSelector("#pp", { timeout: 15_000 });
    await enter(guest);
    await guest.close();
  }

  await landing.close();

  // A 24-hour room must not accuse its own server of tampering. For an
  // absolute TTL the server reports the time *remaining*, which is necessarily
  // less than the duration the config blob records, and the client compared
  // the two directly — so every such room raised the mismatch banner within a
  // minute of being created. A security warning that is always on is worse
  // than none.
  //
  // Created through the landing page rather than by POSTing to the API,
  // because the comparison only runs when a config blob is present and the API
  // does not make one. A version of this check that created the room directly
  // could not fail, and did not: it passed against the unfixed client.
  {
    const ttlPage = await makePage("absolute-ttl");
    await gotoPage(ttlPage, "ttlPage", `${BASE}/`);
    await ttlPage.waitForSelector("#expiry", { timeout: 10_000 });
    await ttlPage.selectOption("#expiry", JSON.stringify({ kind: "absolute", secs: 86400 }));
    await ttlPage.click('button:has-text("Create private room")');
    await ttlPage.waitForSelector(".statusbar", { timeout: 30_000 });

    // The comparison runs once, on JOIN_ACK. Joining the instant the room is
    // made leaves elapsed at zero, where even the broken comparison is quiet —
    // which is why a version of this check that only created and looked passed
    // against the unfixed client. The fault appears on a *later* join, which
    // is exactly how it was reported: a long session, a reconnect, then the
    // banner. Reloading rejoins from the fragment and re-evaluates it.
    await ttlPage.waitForTimeout(5000);
    await ttlPage.reload({ waitUntil: "domcontentloaded" });
    await ttlPage.waitForSelector(".statusbar", { timeout: 30_000 });
    await ttlPage.waitForTimeout(1500);
    const accused = await ttlPage.evaluate(() =>
      document.body.textContent.includes("reports a different expiry"),
    );
    if (accused) {
      throw new Error("[ttl] a 24-hour room reported its own server as contradicting its config");
    }
    await ttlPage.close();
  }

  const alice = await makePage("alice");
  alicePage = alice;
  await gotoPage(alice, "alice", roomUrl);

  // Wait for editor to mount (proves CSP + Trusted Types + WASM all survived)
  await alice.waitForSelector(".monaco-editor", { timeout: 60_000 });
  // Attached, not visible. Monaco's input is a deliberately hidden textarea
  // that follows the cursor, and whether an engine calls it visible is not
  // something the editor promises: macOS Firefox did, Linux Firefox never
  // does. What matters is that it exists before anything is typed.
  await alice.waitForSelector("textarea.inputarea", { state: "attached", timeout: 15_000 });
  await alice.click(".monaco-editor .view-lines");
  await alice.keyboard.type("Hello from Alice. ");

  const bob = await makePage("bob");
  bobPage = bob;
  await gotoPage(bob, "bob", roomUrl);
  await bob.waitForSelector(".monaco-editor", { timeout: 30_000 });
  await bob.click(".monaco-editor .view-lines");
  await bob.keyboard.type("And Bob agrees.");

  // Convergence: Alice's editor must eventually contain Bob's sentence.
  let converged = false;
  for (let i = 0; i < 40 && !converged; i++) {
    const text = await alice.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
    if (text.includes("Bob agrees")) converged = true;
    else await new Promise((r) => setTimeout(r, 250));
  }
  if (!converged) {
    const text = await alice.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
    throw new Error(`convergence failed; preview shows: "${text.slice(0, 200)}"`);
  }

  // Status bar should show 2 peers on both pages
  for (const [label, page] of [["alice", alice], ["bob", bob]]) {
    const peers = await page.evaluate(() =>
      [...document.querySelectorAll(".statusbar .micro-label")].map((e) => e.textContent).join("|"),
    );
    if (!peers.includes("2 PEOPLE")) throw new Error(`[${label}] expected a 2-person count in status bar, got: ${peers}`);
  }

  // The convergence check above compares the *rendered preview*, which
  // normalises whitespace: two sources whose blank lines sit in different
  // places render to identical text. A real divergence report showed exactly
  // that shape — the same words, differently placed — so the preview could
  // never have caught it. Compare the editor's own lines instead.
  /// Put the caret in a page's editor, and make sure it got there.
  ///
  /// Clicking `.view-lines` aims at the centre of that element, and once the
  /// document is longer than the editor that element is taller than the editor
  /// too. Its centre can then sit outside the visible area, the click lands on
  /// whatever covers that point, and the keystrokes after it go to the page
  /// body. That is what the Linux Firefox runner did: focus on <body>, the
  /// typed text nowhere, reported as a shortcut that did not work. This clicks
  /// just inside the top-left of the editor's visible area instead, and then
  /// checks focus is inside the editor, so a miss says what it is.
  const focusEditor = async (page) => {
    const box = await page.locator(".monaco-editor .overflow-guard").first().boundingBox();
    if (!box) throw new Error("[editor] the editor has no visible area to click");
    await page.mouse.click(box.x + Math.min(120, box.width / 2), box.y + Math.min(24, box.height / 2));
    try {
      await page.waitForFunction(() => !!document.activeElement?.closest(".monaco-editor"), null, { timeout: 5000 });
    } catch {
      const focus = await page.evaluate(() => {
        const a = document.activeElement;
        return a ? `${a.tagName.toLowerCase()}.${String(a.className || "").split(" ")[0]}` : "nothing";
      });
      throw new Error(`[editor] clicking the editor did not focus it; focus is on ${focus}`);
    }
  };

  const editorText = (page) =>
    page.evaluate(() =>
      [...document.querySelectorAll(".view-lines .view-line")]
        .map((el) => ({ t: parseInt(el.style.top || "0", 10), x: el.textContent.replace(/\u00a0/g, " ") }))
        .sort((x, y) => x.t - y.t)
        .map((l) => l.x)
        .join("\n"),
    );

  // Type into both at once, at the same place, which is the case that was
  // reported as broken.
  await alice.click(".monaco-editor .view-lines");
  await bob.click(".monaco-editor .view-lines");
  await Promise.all([
    alice.keyboard.type("\nAAAA AAAA AAAA\nAAAA AAAA\n", { delay: 10 }),
    bob.keyboard.type("\nBBBB BBBB BBBB\nBBBB BBBB\n", { delay: 10 }),
  ]);

  let srcA = "";
  let srcB = "";
  for (let i = 0; i < 60; i++) {
    await alice.waitForTimeout(500);
    srcA = await editorText(alice);
    srcB = await editorText(bob);
    if (srcA === srcB && srcA.includes("AAAA") && srcA.includes("BBBB")) break;
  }
  if (srcA !== srcB) {
    throw new Error(
      `[sync] editors did not converge after concurrent typing\n  alice: ${JSON.stringify(srcA)}\n  bob:   ${JSON.stringify(srcB)}`,
    );
  }

  // And the divergence warning must not be crying wolf. It compared the local
  // hash at that instant against hashes peers had broadcast up to a heartbeat
  // earlier, on every update, and latched forever on the first mismatch — so
  // two byte-identical documents both showed it. Waited past the quiet window
  // and a heartbeat so a false positive has every chance to appear.
  await alice.waitForTimeout(13_000);
  for (const [label, page] of [["alice", alice], ["bob", bob]]) {
    const warned = await page.evaluate(() =>
      document.body.textContent.includes("Your copy differs from other peers"),
    );
    if (warned) {
      throw new Error(`[sync] ${label} reports divergence while both editors hold identical text`);
    }
  }

  // Split brain: a peer edits while disconnected, the other edits meanwhile,
  // and both must reconverge on reconnect. This is the highest-risk path in
  // the whole design — it exercises the resync request, the server's log
  // replay and Yjs's merge at once — and it is the shape a real report will
  // most often have, since a phone that locks or a laptop that sleeps looks
  // exactly like this.
  await severNetwork(bob);
  await bob.click(".monaco-editor .view-lines");
  await Promise.all([
    alice.keyboard.type("\nwritten-while-bob-was-away\n", { delay: 8 }),
    bob.keyboard.type("\nwritten-by-bob-offline\n", { delay: 8 }),
  ]);
  await alice.waitForTimeout(2000);
  const splitA = await editorText(alice);
  const splitB = await editorText(bob);
  if (splitA === splitB) {
    throw new Error("[sync] peers did not actually diverge while one was offline — the test proves nothing");
  }
  await restoreNetwork(bob);
  let reA = "";
  let reB = "";
  let reconverged = false;
  for (let i = 0; i < 60; i++) {
    await alice.waitForTimeout(1000);
    reA = await editorText(alice);
    reB = await editorText(bob);
    if (reA === reB) {
      reconverged = true;
      break;
    }
  }
  if (!reconverged) {
    throw new Error(
      `[sync] peers never reconverged after a disconnect\n  alice: ${JSON.stringify(reA)}\n  bob:   ${JSON.stringify(reB)}`,
    );
  }
  if (!reA.includes("written-while-bob-was-away") || !reA.includes("written-by-bob-offline")) {
    throw new Error(`[sync] reconnect lost an edit instead of merging it: ${JSON.stringify(reA)}`);
  }

  const aliceSees = async (marker, seconds) => {
    for (let i = 0; i < seconds; i++) {
      await alice.waitForTimeout(1000);
      if ((await editorText(alice)).includes(marker)) return true;
    }
    return false;
  };

  // A connection that dies without the browser noticing. This is the common
  // case, not the exotic one: a laptop waking, a phone moving between wifi and
  // mobile data. The socket stays OPEN for as long as TCP takes to give up —
  // minutes — and every edit sent into it in that time vanished, with nothing
  // to notice and nothing to send it again. The split-brain test above cannot
  // catch that, because closing the socket is exactly what does not happen.
  await bob.evaluate(() => {
    for (const ws of window.__runaSockets ?? []) ws.__runaDead = true;
  });
  await bob.click(".monaco-editor .view-lines");
  await bob.keyboard.type("\ntyped-into-a-dead-connection\n", { delay: 8 });
  if (await aliceSees("typed-into-a-dead-connection", 3)) {
    throw new Error("[sync] the connection was not actually dead — the test proves nothing");
  }
  if (!(await aliceSees("typed-into-a-dead-connection", 45))) {
    throw new Error("[sync] an edit typed into a silently dead connection never reached the other peer");
  }

  // Typing while the join is still in flight. The socket opens before the
  // server confirms the join, and until it does the client does not know the
  // peer id every receiver checks a frame's authentication against. Edits sent
  // in that window were encrypted under the wrong label: every peer rejected
  // them, the server stored them anyway, and nothing ever sent them again. The
  // delay stands in for a slow round trip, which on a phone is often most of a
  // second.
  const socketsBefore = await bob.evaluate(() => window.__runaSockets.length);
  await bob.evaluate(() => {
    window.__runaDelayInboundMs = 3000;
  });
  await severNetwork(bob);
  await restoreNetwork(bob);
  await bob.waitForFunction(
    (n) => {
      const s = window.__runaSockets;
      return s.length > n && s[s.length - 1].readyState === 1;
    },
    socketsBefore,
    { timeout: 30_000 },
  );
  await bob.click(".monaco-editor .view-lines");
  await bob.keyboard.type("\ntyped-before-the-join-landed\n", { delay: 5 });
  const typedAt = await bob.evaluate(() => Date.now());
  await bob.waitForTimeout(3500);
  const joinLandedAt = await bob.evaluate(() => {
    window.__runaDelayInboundMs = 0;
    const s = window.__runaSockets;
    const live = s[s.length - 1];
    live.__runaDelayMs = 0;
    return live.__runaFirstDeliveredAt ?? null;
  });
  // The edit is flushed within 80 ms of the last keystroke, so the join has to
  // land well after that for the edit to have gone out before it.
  if (joinLandedAt === null || joinLandedAt < typedAt + 300) {
    throw new Error("[sync] the join landed before the typing was sent — the test proves nothing");
  }
  if (!(await aliceSees("typed-before-the-join-landed", 30))) {
    throw new Error("[sync] an edit typed before the join was confirmed never reached the other peer");
  }

  // The status bar counts who is actually here, not who the roster still
  // lists. A roster is a join-time snapshot patched with the events a client
  // happened to receive, so a missed PEER_LEAVE over-counts for the rest of
  // the session — four devices in one room reported 5, 3, 3 and 3 people at
  // the same moment. Presence expires on its own, so the count has to come
  // back down by itself with no event to prompt it, and come back up when the
  // peer returns. Asserted as a round trip because a count that only ever
  // falls is as broken as one that only ever rises.
  const shownPeople = (page) =>
    page.evaluate(() => {
      const m = document.body.textContent.match(/(\d+)\s+(PERSON|PEOPLE)/);
      return m ? Number(m[1]) : null;
    });
  if ((await shownPeople(alice)) !== 2) {
    throw new Error(`[presence] expected 2 people before the drop, saw ${await shownPeople(alice)}`);
  }
  await severNetwork(bob);
  let dropped = false;
  for (let i = 0; i < 50; i++) {
    await alice.waitForTimeout(1000);
    if ((await shownPeople(alice)) === 1) {
      dropped = true;
      break;
    }
  }
  if (!dropped) {
    throw new Error(
      `[presence] a silent peer never expired from the count; still showing ${await shownPeople(alice)}`,
    );
  }
  await restoreNetwork(bob);
  let returned = false;
  for (let i = 0; i < 50; i++) {
    await alice.waitForTimeout(1000);
    if ((await shownPeople(alice)) === 2) {
      returned = true;
      break;
    }
  }
  if (!returned) {
    throw new Error(
      `[presence] the peer came back but the count did not; showing ${await shownPeople(alice)}`,
    );
  }

  // Maths must render as maths, not as flattened text. $E = mc^2$ came out
  // reading "E=mc2" on a real screen while the unit test asserting /katex/i
  // passed the whole time — the wrapper class survives sanitising whether or
  // not anything inside it renders. Structure alone is still not proof, so
  // this measures the rendered geometry: an exponent has to sit higher than
  // its base and be drawn smaller. That is the property that was broken, and
  // it is only observable in a browser.
  await alice.keyboard.type("\n\n$$\nE = mc^2\n$$\n");
  let mathBox = null;
  for (let i = 0; i < 40 && !mathBox; i++) {
    mathBox = await alice.evaluate(() => {
      const base = document.querySelector(".preview-body math mi");
      const exp = document.querySelector(".preview-body math msup mn");
      if (!base || !exp) return null;
      const b = base.getBoundingClientRect();
      const e = exp.getBoundingClientRect();
      if (b.height === 0 || e.height === 0) return null;
      return { baseTop: b.top, baseH: b.height, expTop: e.top, expH: e.height };
    });
    if (!mathBox) await alice.waitForTimeout(150);
  }
  if (!mathBox) throw new Error("[alice] display math never produced MathML in the preview");
  if (!(mathBox.expTop < mathBox.baseTop)) {
    throw new Error(
      `[alice] exponent is not raised above its base (exp top ${Math.round(mathBox.expTop)} vs base ${Math.round(mathBox.baseTop)}) — math is rendering flat`,
    );
  }
  if (!(mathBox.expH < mathBox.baseH)) {
    throw new Error(
      `[alice] exponent is not drawn smaller than its base (${Math.round(mathBox.expH)}px vs ${Math.round(mathBox.baseH)}px)`,
    );
  }
  // Layout used to be one button cycling split → editor → preview, so closing
  // the preview and opening it again cost two presses, and nothing said which
  // mode was current. Each mode is now one press, and the active one is
  // marked. Asserted as a round trip because that is what was reported.
  await alice.setViewportSize({ width: 1280, height: 900 });
  await alice.waitForTimeout(150);
  const previewVisible = () =>
    alice.evaluate(() => {
      const pv = document.querySelector(".pane-preview");
      return !!(pv && getComputedStyle(pv).display !== "none");
    });
  const activeTab = () =>
    alice.evaluate(() => {
      const on = document.querySelector('.mode-tab[aria-pressed="true"]');
      return on ? on.textContent.trim() : null;
    });
  if (!(await previewVisible())) throw new Error("[alice] preview not visible in the default split mode");
  if ((await activeTab()) !== "Split") throw new Error(`[alice] active tab should be Split, got ${await activeTab()}`);

  await alice.click('.mode-tab:has-text("Editor")');
  await alice.waitForTimeout(150);
  if (await previewVisible()) throw new Error("[alice] one press on Editor did not close the preview");
  if ((await activeTab()) !== "Editor") throw new Error("[alice] Editor tab is not marked active after pressing it");

  await alice.click('.mode-tab:has-text("Split")');
  await alice.waitForTimeout(150);
  if (!(await previewVisible())) throw new Error("[alice] one press on Split did not bring the preview back");

  // The pressed tab must be outlined on all four sides in every position.
  // Collapsing the shared borders by deleting each tab's right border left
  // Split and Editor outlined on three sides with a gap on the fourth, while
  // Preview looked correct because it is :last-child and kept its own right
  // border — so eyeballing the control in its default state showed nothing
  // wrong. Measured rather than looked at, in all three positions.
  for (const mode of ["Split", "Editor", "Preview"]) {
    await alice.click(`.mode-tab:has-text("${mode}")`);
    await alice.waitForTimeout(150);
    const edge = await alice.evaluate(() => {
      const el = document.querySelector('.mode-tab[aria-pressed="true"]');
      if (!el) return null;
      const cs = getComputedStyle(el);
      const sides = ["Top", "Right", "Bottom", "Left"];
      return {
        label: el.textContent.trim(),
        widths: sides.map((x) => cs[`border${x}Width`]),
        colors: sides.map((x) => cs[`border${x}Color`]),
      };
    });
    if (!edge) throw new Error(`[tabs] no pressed tab after selecting ${mode}`);
    if (new Set(edge.widths).size !== 1) {
      throw new Error(`[tabs] ${edge.label} is outlined unevenly: ${edge.widths.join(", ")}`);
    }
    if (new Set(edge.colors).size !== 1) {
      throw new Error(`[tabs] ${edge.label} has mismatched border colours: ${edge.colors.join(" | ")}`);
    }
  }
  // And the group must not resize as the selection moves, or the whole bar
  // twitches every time somebody switches pane.
  const groupWidths = [];
  for (const mode of ["Split", "Editor", "Preview"]) {
    await alice.click(`.mode-tab:has-text("${mode}")`);
    await alice.waitForTimeout(120);
    groupWidths.push(
      await alice.evaluate(() => Math.round(document.querySelector(".mode-tabs").getBoundingClientRect().width)),
    );
  }
  if (new Set(groupWidths).size !== 1) {
    throw new Error(`[tabs] the control resizes with the selection: ${groupWidths.join(", ")}`);
  }
  await alice.click('.mode-tab:has-text("Split")');
  await alice.waitForTimeout(150);

  // Split is not offered where it renders identically to editor-only.
  await alice.setViewportSize({ width: 384, height: 780 });
  await alice.waitForTimeout(200);
  await alice.click(".tool-menu-toggle");
  await alice.waitForTimeout(200);
  const narrowTabs = await alice.evaluate(() =>
    [...document.querySelectorAll(".mode-tab")].map((b) => b.textContent.trim()),
  );
  if (narrowTabs.includes("Split")) {
    throw new Error(`[alice] Split offered below the panes breakpoint: ${narrowTabs.join(", ")}`);
  }
  if (!narrowTabs.includes("Editor") || !narrowTabs.includes("Preview")) {
    throw new Error(`[alice] narrow layout tabs missing: ${narrowTabs.join(", ")}`);
  }
  await alice.keyboard.press("Escape");
  await alice.setViewportSize({ width: 1280, height: 900 });
  await alice.waitForTimeout(150);

  // Shred modal opens and shows the honest limitation copy
  await alice.click('button:has-text("Shred")');
  await alice.waitForSelector('[role="alertdialog"]', { timeout: 5000 });
  const modalText = await alice.textContent('[role="alertdialog"]');
  if (!modalText.includes("It cannot reach copies other people already made")) {
    throw new Error("shred modal missing §2.5 limitation copy");
  }

  // The dialog is a confirmation step, not a progress display. Everything
  // gated on the IDLE state — the consensus policy selector above all — has
  // to be on screen when it opens. It previously was not: pressing Shred
  // proposed immediately, so the state was already VOTING by first paint and
  // the selector never rendered. The policy was silently always UNANIMOUS.
  const policySelect = await alice.$('[role="alertdialog"] #shred-policy');
  if (!policySelect) {
    throw new Error(
      "shred modal opened without the consensus policy selector — the dialog " +
        "is proposing before it confirms",
    );
  }
  const policyOptions = await alice.$$eval(
    '[role="alertdialog"] #shred-policy option',
    (els) => els.map((e) => e.value),
  );
  for (const p of ["UNANIMOUS", "MAJORITY", "THRESHOLD"]) {
    if (!policyOptions.includes(p)) throw new Error(`policy ${p} not offered`);
  }
  // INITIATOR let one participant destroy work everyone else was doing.
  if (policyOptions.includes("INITIATOR")) {
    throw new Error("INITIATOR policy is still offered in the UI");
  }

  // The dropdown must survive the expiry countdown, which re-renders the room
  // four times a second. It previously did not: the focus trap re-ran on
  // every render and yanked focus back to Cancel, collapsing the select.
  await alice.selectOption('[role="alertdialog"] #shred-policy', "MAJORITY");
  await new Promise((r) => setTimeout(r, 1200));
  const stillMajority = await alice.$eval(
    '[role="alertdialog"] #shred-policy',
    (el) => el.value,
  );
  if (stillMajority !== "MAJORITY") {
    throw new Error(
      `policy selection did not stick — expected MAJORITY, got ${stillMajority}`,
    );
  }

  // The dialog is where a phone hurts most: two right-aligned buttons on one
  // row ran off the edge of a narrow screen, which is the worst possible
  // place to lose a button. Check the whole page for horizontal overflow at
  // phone widths, with the dialog open.
  for (const width of [320, 375, 414]) {
    await alice.setViewportSize({ width, height: 780 });
    await alice.waitForTimeout(120);
    const bad = await alice.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      const offenders = [];
      for (const el of document.querySelectorAll("*")) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.right > vw + 1) {
          offenders.push(`${el.tagName.toLowerCase()}.${String(el.className || "").split(" ")[0]} right=${Math.round(r.right)}`);
        }
      }
      return { vw, scrollW: document.documentElement.scrollWidth, offenders: offenders.slice(0, 5) };
    });
    if (bad.scrollW > bad.vw + 1) {
      throw new Error(
        `[alice] page scrolls sideways at ${width}px (content ${bad.scrollW}px): ${bad.offenders.join(", ")}`,
      );
    }
    // Both dialog actions must actually be reachable.
    for (const name of ["Cancel", "Shred"]) {
      const box = await alice.locator(`[role="alertdialog"] button:has-text("${name}")`).first().boundingBox();
      if (!box) throw new Error(`[alice] "${name}" button missing at ${width}px`);
      if (box.x < 0 || box.x + box.width > width + 1) {
        throw new Error(`[alice] "${name}" button off-screen at ${width}px (x=${Math.round(box.x)} w=${Math.round(box.width)})`);
      }
    }
  }
  // The room must fit the window exactly. It did not: the editor pane was a
  // plain block holding the markdown ribbon and an editor sized at height:100%
  // of that same block, so the two came to a ribbon's height more than the
  // window. The document scrolled as a whole — a second scrollbar beside the
  // editor's own, and the status bar and ribbon sliding off the top, which
  // looked like rows pinning themselves under the toolbar.
  //
  // The guard beside this one checks the *horizontal* axis only, which is why
  // 30px of vertical overflow sat there unnoticed across three engines.
  for (const [w, h] of [[1400, 800], [1280, 720], [1024, 900]]) {
    await alice.setViewportSize({ width: w, height: h });
    await alice.waitForTimeout(400);
    const fit = await alice.evaluate(() => {
      const de = document.documentElement;
      window.scrollTo(0, 0);
      return { over: de.scrollHeight - de.clientHeight, root: document.querySelector("#root")?.getBoundingClientRect().height };
    });
    if (fit.over > 1) {
      throw new Error(`[room] the page scrolls at ${w}x${h}: ${fit.over}px past the window (#root ${Math.round(fit.root)})`);
    }
    // And nothing may drag the chrome off the top.
    await alice.evaluate(() => window.scrollTo(0, 500));
    await alice.waitForTimeout(200);
    const barTop = await alice.evaluate(() => Math.round(document.querySelector(".statusbar").getBoundingClientRect().top));
    if (barTop < -1) {
      throw new Error(`[room] the status bar scrolled off the top at ${w}x${h} (top ${barTop})`);
    }
  }
  await alice.setViewportSize({ width: 1280, height: 900 });
  await alice.waitForTimeout(300);

  // Side-by-side panes on a screen too narrow for them is how a shared room
  // link arrives looking like a blank page: two empty pane backgrounds with
  // the text off in the top-left. Reported from a Realme handset, where the
  // cause was Android's "Desktop site" toggle forcing a 980px layout viewport
  // — a width no phone reports natively, so no phone-width check could see
  // it. The same band catches any handset turned sideways (932px at the
  // widest) and a small tablet in portrait (834px).
  for (const [width, wantSplit] of [[834, false], [932, false], [980, false], [1024, true]]) {
    await alice.setViewportSize({ width, height: 800 });
    await alice.waitForTimeout(150);
    const split = await alice.evaluate(() => {
      const pv = document.querySelector(".pane-preview");
      return !!(pv && getComputedStyle(pv).display !== "none");
    });
    if (split !== wantSplit) {
      throw new Error(
        `[alice] at ${width}px the room shows ${split ? "two panes" : "one pane"}, expected ${wantSplit ? "two" : "one"}`,
      );
    }
  }

  // Copy link and Shred stay on the bar at phone width; everything else folds
  // into the overflow menu. Shred behind a menu would be the wrong thing to
  // make slower, and a menu that will not close is a trap on a touch screen.
  await alice.setViewportSize({ width: 384, height: 780 });
  await alice.waitForTimeout(150);
  const bar = await alice.evaluate(() => {
    const vis = (el) => !!el && getComputedStyle(el).display !== "none";
    const items = document.querySelector(".tool-menu-items");
    return {
      copy: [...document.querySelectorAll(".statusbar-actions button")].some((b) => /Copy link/.test(b.textContent)),
      shred: [...document.querySelectorAll(".statusbar-actions button")].some((b) => /Shred/.test(b.textContent)),
      toggle: vis(document.querySelector(".tool-menu-toggle")),
      menuClosed: !!items && getComputedStyle(items).display === "none",
    };
  });
  if (!bar.copy || !bar.shred) throw new Error("[alice] Copy link and Shred must stay visible at 384px");
  if (!bar.toggle) throw new Error("[alice] overflow menu toggle missing at 384px");
  if (!bar.menuClosed) throw new Error("[alice] overflow menu is open before it is asked for");

  await alice.setViewportSize({ width: 1280, height: 900 });

  await alice.click('[role="alertdialog"] button:has-text("Cancel")');

  // Ctrl/Cmd+B and Ctrl/Cmd+I do nothing in a standalone Monaco — bold and
  // italic are commands VS Code supplies for markdown — so in a markdown
  // editor they failed silently, which reads as broken rather than absent.
  // Checked through the keyboard rather than by asking whether the action is
  // registered: a registered action with the wrong keybinding would satisfy
  // the second and still leave the shortcut dead.
  //
  // The modifier comes from the page, not the host. Monaco decides whether
  // CtrlCmd means Cmd by looking for "Macintosh" in the user agent, and
  // Playwright's WebKit reports a macOS user agent on every host — while
  // `ControlOrMeta` is resolved from the machine running the test. On a Linux
  // runner that pressed Ctrl into an editor listening for Cmd, and the
  // shortcut looked dead in exactly the one engine where it was fine.
  const mod = (await alice.evaluate(() => navigator.userAgent.includes("Macintosh"))) ? "Meta" : "Control";
  // And end-of-document is not the same chord on both: Monaco binds it to
  // Cmd+Down on a Mac and Ctrl+End elsewhere, so Cmd+End moved nothing and the
  // text below only landed at the end because the cursor was already there.
  const docEnd = mod === "Meta" ? "Meta+ArrowDown" : "Control+End";
  await focusEditor(alice);
  await alice.keyboard.press(docEnd);
  await alice.keyboard.press("Enter");
  await alice.keyboard.type("emphasise-me");
  // Wait for the rendered line rather than pausing a fixed time. By here the
  // document has grown past the fold, so the typed line is only drawn once the
  // editor has scrolled to it, and on a slow runner that takes longer than any
  // pause worth hard-coding. Checked before the shortcut too, so a failure says
  // whether the typing or the shortcut is what went missing.
  const lineWith = async (want) => {
    let seen = "";
    for (let i = 0; i < 50; i++) {
      seen = await alice.evaluate(() => {
    const rows = [...document.querySelectorAll(".view-lines .view-line")]
      .map((el) => ({ t: parseInt(el.style.top || "0", 10), x: el.textContent.replace(/\u00a0/g, " ") }))
      .sort((a, b) => a.t - b.t);
    return rows.map((r) => r.x).find((x) => x.includes("emphasise-me")) ?? "";
  });
      if (seen.includes(want)) return seen;
      await alice.waitForTimeout(100);
    }
    return seen;
  };
  if (!(await lineWith("emphasise-me"))) {
    throw new Error("[shortcuts] the typed text never appeared in the editor, so the shortcut was never tried");
  }
  for (let i = 0; i < "emphasise-me".length; i++) await alice.keyboard.press("Shift+ArrowLeft");
  await alice.keyboard.press(`${mod}+b`);
  let line = await lineWith("**emphasise-me**");
  if (!line.includes("**emphasise-me**")) {
    throw new Error(`[shortcuts] Ctrl/Cmd+B did not bold the selection: ${JSON.stringify(line)}`);
  }
  for (let i = 0; i < "**emphasise-me**".length; i++) await alice.keyboard.press("Shift+ArrowLeft");
  await alice.keyboard.press(`${mod}+i`);
  line = await lineWith("***emphasise-me***");
  if (!line.includes("***emphasise-me***")) {
    throw new Error(`[shortcuts] Ctrl/Cmd+I did not italicise the selection: ${JSON.stringify(line)}`);
  }

  // Sticky scroll stays off. Monaco turns it on by default and pins the
  // enclosing foldable block's header to the top of the editor; with no
  // folding provider for markdown it folds by indentation, so it pinned rows
  // of dashes and ordinary sentences that happened to precede indented text,
  // and cost up to 90px of editor height.
  //
  // The content below matters: three earlier attempts to measure this used
  // flat documents, which produce no folding ranges at all, so the widget was
  // zero-height whether the feature was on or off and every one of them
  // reported it inert. Indentation is what makes this able to fail.
  await focusEditor(alice);
  await alice.keyboard.press(docEnd);
  await alice.keyboard.type("\nblock header\n");
  // Longer than the viewport on purpose: a block that fits on screen keeps its
  // header visible, so there is nothing to pin and the check passes whatever
  // the setting is. That was the first version of this.
  for (let i = 0; i < 45; i++) await alice.keyboard.type(`    indented body ${i}\n`);
  await alice.waitForTimeout(600);
  await alice.mouse.move(600, 400);
  for (let i = 0; i < 6; i++) {
    await alice.mouse.wheel(0, 200);
    await alice.waitForTimeout(150);
  }
  await alice.waitForTimeout(400);
  const sticky = await alice.evaluate(() => {
    const w = document.querySelector(".sticky-widget");
    const r = w?.getBoundingClientRect();
    return { h: r ? Math.round(r.height) : -1, text: (w?.textContent ?? "").trim().slice(0, 40) };
  });
  if (sticky.h > 0) {
    throw new Error(`[sticky] the editor is pinning a block header again: ${sticky.h}px "${sticky.text}"`);
  }

  // Right-click has to offer Cut, Copy and Paste, and Paste has to take one
  // click.
  //
  // Turning Monaco's menu off everywhere left right-click useless: on
  // Monaco's rendered text the platform menu is a generic page menu with no
  // Cut or Copy, since the glyphs are divs and the real input is hidden. And
  // in Firefox and Safari Monaco's own Paste can never be one click — it reads
  // the clipboard from script, which those two answer with a Paste button of
  // their own. So Chromium keeps Monaco's menu, and Firefox and WebKit get the
  // browser's own menu, opened over a stand-in holding the selection, whose
  // Paste is a real one.
  //
  // A native menu cannot be driven from here, so the WebKit and Firefox half
  // proves what the menu depends on instead: that the menu event really lands
  // on the stand-in and is left to open, that the stand-in holds the
  // selection selected — what makes the browser enable Cut and Copy — and
  // that the copy and paste events the menu's items produce reach the editor.
  //
  // Those events are replayed with a clipboard object the test can read. A
  // ClipboardEvent built by script is not the one a menu produces: Firefox
  // hands its listeners a copy of the DataTransfer it was given, so what a
  // handler writes never reaches the object the test holds. A real Copy from
  // the menu is a trusted event whose clipboardData is written through, which
  // is what Monaco's own copy has always relied on.
  const menuMarker = `menu-${Date.now().toString(36)}`;
  await focusEditor(alice);
  await alice.keyboard.type(`\n${menuMarker}`, { delay: 5 });
  await alice.keyboard.press("Shift+Home");
  await alice.evaluate(() => {
    window.__ctx = null;
    window.addEventListener(
      "contextmenu",
      // Capture, because Monaco calls stopPropagation. Sampled after the
      // whole dispatch, so every handler has had its say.
      (e) =>
        setTimeout(() => {
          window.__ctx = { prevented: e.defaultPrevented, target: String(e.target?.className ?? "") };
        }, 0),
      true,
    );
  });
  const rightClickSelection = async () => {
    const box = await alice.locator(".view-lines .view-line", { hasText: menuMarker }).first().boundingBox();
    if (!box) throw new Error("[contextmenu] the selected line is not on screen");
    // Inside the selection, which a right-click keeps.
    await alice.mouse.click(box.x + 12, box.y + box.height / 2, { button: "right" });
    await alice.waitForTimeout(400);
    return alice.evaluate(() => window.__ctx);
  };
  const ctx = await rightClickSelection();
  if (ctx === null) throw new Error("[contextmenu] no contextmenu event reached the page");
  if (ENGINE_NAME === "chromium") {
    if (ctx.prevented !== true) {
      throw new Error("[contextmenu] the editor has no context menu of its own — right-click falls back to a generic page menu with no Cut or Copy");
    }
    const menuItems = (await alice.locator(".monaco-menu .action-label").allTextContents()).filter((t) => t.trim());
    for (const needed of ["Cut", "Copy", "Paste"]) {
      if (!menuItems.includes(needed)) {
        throw new Error(`[contextmenu] the editor's menu has no ${needed}: ${JSON.stringify(menuItems)}`);
      }
    }
    await alice.keyboard.press("Escape");
  } else {
    if (ctx.prevented !== false || !ctx.target.includes("runa-menu-stand-in")) {
      throw new Error(
        `[contextmenu] ${ENGINE_NAME} must open its own menu over the stand-in, got target "${ctx.target}", prevented ${ctx.prevented}`,
      );
    }
    const monacoItems = (await alice.locator(".monaco-menu .action-label").allTextContents()).filter((t) => t.trim());
    if (monacoItems.length) {
      throw new Error(`[contextmenu] Monaco's menu opened too, so there are two menus: ${JSON.stringify(monacoItems)}`);
    }
    const copied = await alice.evaluate(() => {
      const el = document.activeElement;
      if (!el?.classList.contains("runa-menu-stand-in")) return { error: `focus is on ${el?.tagName} ${el?.className}` };
      const selected = el.value.slice(el.selectionStart, el.selectionEnd);
      const written = {};
      const copy = new Event("copy", { bubbles: true, cancelable: true });
      Object.defineProperty(copy, "clipboardData", {
        value: { setData: (t, v) => { written[t] = v; }, getData: (t) => written[t] ?? "" },
      });
      el.dispatchEvent(copy);
      return { selected, copied: written["text/plain"] ?? "", left: !!document.querySelector(".runa-menu-stand-in") };
    });
    if (copied.error) throw new Error(`[contextmenu] the stand-in does not have focus, so the menu's items would miss it: ${copied.error}`);
    if (copied.selected !== menuMarker) {
      throw new Error(`[contextmenu] the stand-in does not hold the selection, so the browser would grey out Cut and Copy: "${copied.selected}"`);
    }
    if (copied.copied !== menuMarker) throw new Error(`[contextmenu] Copy from the browser's menu copied "${copied.copied}"`);
    if (copied.left) throw new Error("[contextmenu] the stand-in stayed behind after Copy");

    const pasted = `pasted-${menuMarker}`;
    await rightClickSelection();
    await alice.evaluate((text) => {
      const paste = new Event("paste", { bubbles: true, cancelable: true });
      Object.defineProperty(paste, "clipboardData", {
        value: { getData: (t) => (t === "text/plain" ? text : ""), setData: () => {} },
      });
      document.activeElement?.dispatchEvent(paste);
    }, pasted);
    let shown = "";
    for (let i = 0; i < 20 && !shown.includes(pasted); i++) {
      await alice.waitForTimeout(150);
      shown = await alice.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
    }
    if (!shown.includes(pasted)) throw new Error("[contextmenu] Paste from the browser's menu did not reach the document");
    if (await alice.locator(".runa-menu-stand-in").count()) {
      throw new Error("[contextmenu] the stand-in stayed behind after Paste");
    }
  }


  // A shred request must survive a reconnect. Reported from two machines: a
  // laptop that had switched tabs a couple of times proposed a shred, showed
  // the right occupant count, and the other machine — online the entire time —
  // never saw the prompt at all. Only a full page reload restored it.
  //
  // The cause was that JOIN_ACK's authoritative roster was merged into the
  // existing map rather than replacing it, so each reconnect left the previous
  // connection's peer id behind. The roster is the consensus denominator AND
  // its hash travels inside the request, so an inflated roster asked three of
  // four to approve and hashed differently from everyone else's, and every
  // receiver dropped the request as `roster-mismatch`. Silently, because the
  // guard hook was an empty function.
  await severNetwork(bob);
  await bob.waitForTimeout(1500);
  await restoreNetwork(bob);
  let backTogether = false;
  for (let i = 0; i < 60; i++) {
    await alice.waitForTimeout(1000);
    const n = await alice.evaluate(() => {
      const m = document.body.textContent.match(/(\d+)\s+(PERSON|PEOPLE)/);
      return m ? Number(m[1]) : null;
    });
    if (n === 2) {
      backTogether = true;
      break;
    }
  }
  if (!backTogether) throw new Error("[shred] peers never re-established before the shred check");

  // Scope: this now does reproduce the roster merge that caused the reported
  // failure, which it could not before. The previous note here said so
  // honestly — a brief setOffline blip never produced a real socket close, so
  // there was no second JOIN_ACK to merge a stale peer id out of, and the test
  // stayed green with the fix reverted. severNetwork() does produce one.
  // Rechecked the only way worth trusting: drop the `target.clear()` from
  // replaceRoster and this fails with a denominator of 5 for two people.
  //
  // So the path is covered end to end — a shred proposed after a real
  // interruption reaches the other side, and the bar it asks for describes the
  // people actually in the room. session.roster.test.ts still asserts the
  // merge directly; this is the same bug seen from the outside. Bob proposes
  // because bob is the one that dropped.
  await bob.click('button:has-text("Shred")');
  await bob.waitForSelector('[role="alertdialog"]', { timeout: 5000 });

  // The denominator has to describe the people who are here. A reconnect used
  // to inflate it, so this asked three of four with two people in the room.
  await bob.selectOption('[role="alertdialog"] #shred-policy', "THRESHOLD");
  await bob.waitForTimeout(200);
  const policyCopy = await bob.textContent('[role="alertdialog"]');
  const denom = policyCopy.match(/of\s+(?:the\s+)?(\d+)/);
  if (!denom || Number(denom[1]) !== 2) {
    throw new Error(`[shred] consensus denominator is ${denom ? denom[1] : "unreadable"} with two people present`);
  }
  await bob.selectOption('[role="alertdialog"] #shred-policy', "UNANIMOUS");
  await bob.waitForTimeout(200);
  await bob.click('[role="alertdialog"] button:has-text("Shred")');

  // And the other side must actually be asked.
  try {
    await alice.waitForSelector('text=SHRED REQUESTED BY A PEER', { timeout: 15000 });
  } catch {
    throw new Error("[shred] the peer was never prompted — the request was dropped in silence");
  }
  await alice.click('[role="alertdialog"] button:has-text("Reject")');
  await bob.waitForTimeout(500);

  // Export offered PDF at one fixed size and nothing else: a long document
  // became sixty-odd pages with no way to change it, and there was no way to
  // get the source back out at all. The dialog now offers both, and this
  // checks the markdown path end to end — a download that never arrives is
  // indistinguishable from a button that does nothing.
  alice.on("dialog", (d) => void d.accept());
  await alice.click('button:has-text("Export")');
  await alice.waitForSelector('[role="dialog"]', { timeout: 5000 });
  const offered = await alice.evaluate(() =>
    [...document.querySelectorAll('[role="dialog"] button')].map((b) => b.textContent.trim()),
  );
  for (const want of ["Markdown (.md)", "Compact", "Normal", "Large"]) {
    if (!offered.includes(want)) {
      throw new Error(`[export] the dialog does not offer "${want}": ${offered.join(", ")}`);
    }
  }
  const download = alice.waitForEvent("download", { timeout: 15_000 });
  await alice.click('[role="dialog"] button:has-text("Markdown (.md)")');
  const file = await download;
  if (!/^runa-\d{8}-\d{4}\.md$/.test(file.suggestedFilename())) {
    throw new Error(`[export] unexpected filename: ${file.suggestedFilename()}`);
  }
  // A file that outlives the room must not carry the room's address into a
  // downloads folder, a backup, and whatever syncs them.
  if (file.suggestedFilename().includes(roomIdHex.slice(0, 8))) {
    throw new Error("[export] the filename leaks the room id");
  }
  const saved = await file.path();
  const contents = saved ? await (await import("node:fs/promises")).readFile(saved, "utf8") : "";
  if (!contents.includes("Hello from Alice")) {
    throw new Error(`[export] the markdown does not contain the document: ${JSON.stringify(contents.slice(0, 120))}`);
  }

  // Tombstone reachable and header-clean
  const gone = await fetch(`${BASE}/gone.html`);
  if (!gone.headers.get("clear-site-data")) throw new Error("gone.html missing Clear-Site-Data");
  // Comments stripped first: the file explains the old placeholder in a
  // comment, and a check that trips on its own documentation is a bad check.
  // Repeated until nothing changes, so a comment that a single pass would
  // reassemble out of the pieces around it ("<!<!---->--") is gone too.
  let goneBody = await gone.text();
  for (let prev = ""; prev !== goneBody; ) {
    prev = goneBody;
    goneBody = goneBody.replace(/<!--[\s\S]*?-->/g, "");
  }
  // It used to read "ROOM —— · SHREDDED —— UTC", with the dashes standing in
  // for values no script ever supplied — the element was referenced nowhere —
  // so every reader saw the placeholders themselves.
  if (/——/.test(goneBody)) {
    throw new Error("gone.html still shows unfilled placeholders");
  }
  // And it must stay anonymous: this page is served with Clear-Site-Data, so
  // naming the room here would write that address into a history just wiped
  // for exactly that reason.
  if (/room[_-]?id|\bUTC\b/i.test(goneBody)) {
    throw new Error("gone.html leaks room or timing detail");
  }

  const cspViolations = errors.filter((e) => /Content Security Policy|trustedTypes|Refused to/i.test(e));
  if (cspViolations.length > 0) {
    console.error("CSP/TT VIOLATIONS:");
    for (const e of cspViolations.slice(0, 10)) console.error(" ", e);
    throw new Error(`${cspViolations.length} CSP/Trusted-Types violations`);
  }

  // iOS Safari zooms the page when focus lands on a control computing under
  // 16px, and never undoes it — so tapping a line to type left the reader
  // zoomed in, and the shred dialog (position:fixed, laid out against the
  // layout viewport) then rendered cropped at both edges. Monaco's hidden
  // input was 12px and is written inline by Monaco, so no stylesheet rule
  // reached it; the fix is the editor option, keyed on pointer type.
  //
  // Checked under real touch emulation, because that is what the fix keys on:
  // with pointer:fine the desktop sizes are correct and prove nothing.
  const touchCtx = await browser.newContext({
    viewport: { width: 393, height: 852 },
    hasTouch: true,
    isMobile: true,
  });
  const touch = await touchCtx.newPage();
  await gotoPage(touch, "touch", roomUrl);
  // Counted from commit now, not DOMContentLoaded, so it covers the scripts
  // loading as well as the room coming up.
  await touch.waitForSelector(".pane-editor", { timeout: 30_000 });
  await touch.waitForTimeout(1500);
  const zoomers = await touch.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll("input, select, textarea")) {
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden") continue;
      const fs = parseFloat(cs.fontSize);
      if (fs < 16) out.push(`${el.tagName.toLowerCase()}.${String(el.className || "").split(" ")[0]}=${fs}px`);
    }
    return out;
  });
  await touchCtx.close();
  if (zoomers.length > 0) {
    throw new Error(
      `[touch] controls under the 16px iOS zoom threshold: ${zoomers.join(", ")}`,
    );
  }

  // A restart warns every open room before the process stops. The two peers
  // are still in their room, so SIGTERM — what systemd sends on a redeploy —
  // has to reach both as a countdown, and the server has to wait it out rather
  // than vanish with their documents.
  //
  // Then the room has to survive it. A redeploy used to end every room
  // mid-session; now the stopping process hands each member a ticket and the
  // new one takes the room back from them. Written before the restart, this
  // marker must be readable afterwards by someone who was never in the room
  // before — the only way it can reach them is through the new server's log,
  // refilled from the members' own copies.
  const marker = `kept-across-restart-${Date.now().toString(36)}`;
  // The whole document, from the preview: the editor renders only the lines
  // in view, and by now the document is longer than the editor.
  const docText = (page) =>
    page.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
  // Earlier checks can leave a shred dialog open, and it covers the editor.
  for (const page of [alice, bob]) {
    for (let i = 0; i < 3; i++) {
      const dialog = page.locator('[role="dialog"], [role="alertdialog"]').first();
      if (!(await dialog.count())) break;
      const dismiss = dialog.locator('button:has-text("Cancel"), button:has-text("Reject")').first();
      if (await dismiss.count()) await dismiss.click();
      else await page.keyboard.press("Escape");
      await page.waitForTimeout(100);
    }
  }
  await focusEditor(alice);
  await alice.keyboard.press("ControlOrMeta+End");
  await alice.keyboard.type(`\n${marker}\n`, { delay: 5 });
  for (let i = 0; i < 40 && !(await docText(bob)).includes(marker); i++) await bob.waitForTimeout(250);
  if (!(await docText(bob)).includes(marker)) throw new Error("[restart] the marker never reached bob");

  server.kill("SIGTERM");
  const warned = (page) =>
    page.waitForSelector('.banner:has-text("restarts in")', { timeout: 4000 }).then(
      () => true,
      () => false,
    );
  const [aliceWarned, bobWarned] = await Promise.all([warned(alice), warned(bob)]);
  if (!aliceWarned || !bobWarned) {
    throw new Error(`[restart] SIGTERM did not warn every open room (alice ${aliceWarned}, bob ${bobWarned})`);
  }
  const warning = (await alice.locator(".banner", { hasText: "restarts in" }).first().textContent()) ?? "";
  if (!warning.includes("Keep this tab open")) {
    throw new Error(`[restart] with a restart key the warning must say the room carries over: "${warning}"`);
  }
  if (server.exitCode !== null || server.signalCode !== null) {
    throw new Error("[restart] the server stopped without waiting out its warning");
  }
  const stopped = await Promise.race([
    waitForProcessExit(server).then(() => true),
    new Promise((r) => setTimeout(() => r(false), 20_000)),
  ]);
  if (!stopped) throw new Error("[restart] the server never stopped after its warning");

  await startServer();
  const cleared = (page) =>
    page
      .waitForFunction(
        () => !document.body.textContent.includes("restarts in") && !!document.querySelector(".monaco-editor"),
        null,
        { timeout: 30_000 },
      )
      .then(
        () => true,
        () => false,
      );
  const [aliceBack, bobBack] = await Promise.all([cleared(alice), cleared(bob)]);
  if (!aliceBack || !bobBack) {
    const shown = await alice.evaluate(() => document.body.textContent.replace(/\s+/g, " ").slice(0, 300));
    throw new Error(`[restart] the room did not come back on the new server (alice ${aliceBack}, bob ${bobBack}): ${shown}`);
  }
  const after = `typed-after-restart-${Date.now().toString(36)}`;
  await focusEditor(bob);
  await bob.keyboard.press("ControlOrMeta+End");
  await bob.keyboard.type(`\n${after}\n`, { delay: 5 });
  for (let i = 0; i < 60 && !(await docText(alice)).includes(after); i++) await alice.waitForTimeout(250);
  if (!(await docText(alice)).includes(after)) {
    throw new Error("[restart] after the handover, an edit on one side never reached the other");
  }
  const carol = await makePage("carol");
  await gotoPage(carol, "carol", roomUrl);
  await carol.waitForSelector(".monaco-editor", { timeout: 30_000 });
  let carolSees = "";
  for (let i = 0; i < 60; i++) {
    carolSees = await carol.evaluate(() => document.querySelector(".pane-preview .preview-body")?.textContent ?? "");
    if (carolSees.includes(marker) && carolSees.includes(after)) break;
    await carol.waitForTimeout(250);
  }
  if (!carolSees.includes(marker)) {
    const carolState = await carol.evaluate(() => ({
      body: document.body.textContent.replace(/\s+/g, " ").slice(0, 300),
      lines: document.querySelectorAll(".view-lines .view-line").length,
    }));
    throw new Error(
      `[restart] someone joining after the restart does not see what was written before it: "${carolSees.slice(-200)}" ${JSON.stringify(carolState)}`,
    );
  }

  await browser.close();

  console.log(`BROWSER E2E OK (${ENGINE_NAME})`);
  console.log(`  the key never stays in the address: Join, a clicked link, and room creation`);
  console.log(`  highest security: not saved, forgotten on refresh, Copy link still whole`);
  console.log(`  key rotation: a departed peer's key opens nothing written after it; a newcomer is handed the keys and reads the history`);
  console.log(`  shared rooms: highest keeps the name out of the address; everyday takes it after joining`);
  console.log(`  two headless peers joined ${roomIdHex.slice(0, 8)}…`);
  console.log(`  typed concurrently; Alice's preview converged to include Bob's text`);
  console.log(`  status bars showed a 2-person count on both sides`);
  console.log(`  editors converged char-for-char after concurrent typing; no false divergence`);
  console.log(`  offline edits on both sides reconverged on reconnect, nothing lost`);
  console.log(`  an edit typed into a silently dead connection still reached the other peer`);
  console.log(`  an edit typed before the join was confirmed still reached the other peer`);
  console.log(`  presence count falls when a peer goes quiet and returns when it comes back`);
  console.log(`  a shred proposed after a reconnect reaches the peer, and counts only who is here`);
  console.log(`  export offers markdown and three PDF sizes; the .md lands with the source in it`);
  console.log(`  shred modal: three safe policies, selection sticks, cancel works`);
  console.log(`  landing and room hold 320 / 375 / 414 px; dialog buttons reachable`);
  console.log(`  a 24-hour room does not accuse its server of changing the expiry`);
  console.log(`  named-room form strands nothing above the scroll origin on four phones`);
  console.log(`  a name already in use is refused as taken, before any key derivation`);
  console.log(`  a room link pasted into Join on the front page opens the room, key included`);
  console.log(`  a named room opens in another page with the passphrase it was made with`);
  console.log(`  room stays one pane to 1000px; Copy link and Shred stay on the bar`);
  console.log(`  the room fits the window exactly; the chrome cannot scroll away`);
  console.log(`  ctrl/cmd+B and +I emphasise through the keyboard; right-click offers Cut, Copy and a one-click Paste in every engine`);
  console.log(`  no block header pins itself to the top of an indented document`);
  console.log(`  no control under the 16px iOS zoom threshold on a touch device`);
  console.log(`  a restart warns both open rooms with a countdown, and the server waits it out`);
  console.log(`  the room carries over to the next server process, and a newcomer reads what was written before it`);
  console.log(`  display math renders with the exponent raised and smaller`);
  console.log(`  layout tabs: one press per mode, active marked, no Split on a phone`);
  console.log(`  pressed tab outlined evenly on all four sides; control does not resize`);
  console.log(`  gone.html served with Clear-Site-Data, anonymous, no placeholder text`);
  console.log(`  zero CSP / Trusted-Types violations across both sessions`);
  process.exit(0);
}

main().catch(async (e) => {
  console.error("BROWSER E2E FAILED:", e.message);
  if (alicePage && !alicePage.isClosed()) {
    try {
      const body = await alicePage.evaluate(() =>
        document.body.innerHTML.replace(/\s+/g, " ").slice(0, 400),
      );
      console.error("ALICE BODY:", body);
      console.error("ALICE URL:", alicePage.url());
    } catch {}
  }
  // What each peer's page looked like at the moment of failure. A CI-only
  // failure cannot be reproduced locally, and "the text is not there" says
  // nothing about whether it was never typed, typed somewhere else, or is
  // hidden behind something.
  for (const [label, page] of [["alice", alicePage], ["bob", bobPage]]) {
    if (!page || page.isClosed()) continue;
    try {
      const state = await Promise.race([
        page.evaluate(() => {
          const name = (el) =>
            el ? `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}.${String(el.className || "").split(" ")[0]}` : "none";
          const lines = [...document.querySelectorAll(".view-lines .view-line")]
            .map((el) => ({ t: parseInt(el.style.top || "0", 10), x: el.textContent }))
            .sort((p, q) => p.t - q.t);
          return {
            focus: name(document.activeElement),
            dialogs: [...document.querySelectorAll('[role="dialog"], [role="alertdialog"]')].map((d) =>
              d.textContent.trim().slice(0, 80),
            ),
            alerts: [...document.querySelectorAll('[role="alert"], .banner, .toast')]
              .map((d) => d.textContent.trim().slice(0, 80))
              .filter(Boolean),
            renderedLines: lines.length,
            lastLines: lines.slice(-4).map((l) => l.x),
          };
        }),
        new Promise((r) => setTimeout(() => r("page did not answer within 3s"), 3000)),
      ]);
      console.error(`${label.toUpperCase()} STATE:`, JSON.stringify(state));
    } catch {}
  }
  // Grouped by page. One peer's expected noise — a severed socket logs a
  // connection error on every retry — used to fill the whole allowance and
  // hide the one error from the other page that explained the failure.
  const byPage = new Map();
  for (const err of errors) {
    const label = /^\[([^\]]+)\]/.exec(err)?.[1] ?? "?";
    if (!byPage.has(label)) byPage.set(label, []);
    byPage.get(label).push(err);
  }
  for (const [label, list] of byPage) {
    console.error(` captured from ${label}: ${list.length}, last ${Math.min(list.length, 5)}:`);
    for (const err of list.slice(-5)) console.error("   ", err.slice(0, 300));
  }
  if (serverLogRef?.length) {
    const lines = serverLogRef.join("").replace(/\x1b\[[0-9;]*m/g, "").split("\n").filter(Boolean);
    console.error(`SERVER LOG (last ${Math.min(lines.length, 40)} of ${lines.length} lines):`);
    for (const l of lines.slice(-40)) console.error("  " + l.slice(0, 300));
  }
  process.exit(1);
});
