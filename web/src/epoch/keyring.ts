import {
  confirmsEqual,
  EPOCH_SECRET_LEN,
  rootEpochKeys,
  stepKeys,
  type EpochKeys,
} from "../crypto/epoch";

/// Every epoch key a member holds for one room, from its root to now, and the
/// raw secrets that step it forward. The secrets are what a newcomer is
/// handed; each derives the keys itself from its own link or passphrase, so no
/// key ever leaves a browser (PROTOCOL.md amendment J). Keeping the older keys
/// is what lets a replayed log, which spans epochs, be read.
export class Keyring {
  private keys = new Map<number, EpochKeys>();
  private secrets: Uint8Array[] = [];
  private cur: EpochKeys;
  private tail: Promise<unknown> = Promise.resolve();
  private dead = false;
  readonly rootEpoch: number;

  private constructor(root: EpochKeys) {
    this.cur = root;
    this.rootEpoch = root.epoch;
    this.keys.set(root.epoch, root);
  }

  static async fromRoot(epoch: number, contentKey: CryptoKey, chainKey: CryptoKey): Promise<Keyring> {
    return new Keyring(await rootEpochKeys(epoch, contentKey, chainKey));
  }

  get current(): EpochKeys {
    return this.cur;
  }

  get wiped(): boolean {
    return this.dead;
  }

  /// Mutators interleave across awaits, so each runs to completion before the
  /// next starts. A failure in one must not stall the ones behind it.
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.tail.then(fn, fn);
    this.tail = run.catch(() => undefined);
    return run;
  }

  has(epoch: number): boolean {
    return this.keys.has(epoch);
  }

  keyFor(epoch: number): CryptoKey | null {
    if (this.dead) return null;
    return this.keys.get(epoch)?.contentKey ?? null;
  }

  /// Commit a step, but only if it is the next epoch and what it derives
  /// matches the confirmation the rotator sent. Otherwise nothing changes.
  applyStep(to: number, secret: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    return this.serial(() => this.stepNow(to, secret, expectedConfirm));
  }

  private async stepNow(to: number, secret: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    if (this.dead || to !== this.cur.epoch + 1 || secret.length !== EPOCH_SECRET_LEN) return null;
    const next = await stepKeys(this.cur, secret);
    if (this.dead || !confirmsEqual(next.confirm, expectedConfirm)) return null;
    this.secrets.push(secret.slice());
    this.keys.set(next.epoch, next);
    this.cur = next;
    return next;
  }

  /// Catch up from the root with the secrets a member handed over.
  applyHandover(to: number, secretsBlob: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    return this.serial(() => this.handoverNow(to, secretsBlob, expectedConfirm));
  }

  private async handoverNow(to: number, secretsBlob: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    if (this.dead) return null;
    const count = to - this.rootEpoch;
    if (to <= this.cur.epoch || count <= 0 || secretsBlob.length !== count * EPOCH_SECRET_LEN) return null;
    const root = this.keys.get(this.rootEpoch);
    if (!root) return null;
    const list: Uint8Array[] = [];
    let committed = false;
    try {
      const derived: EpochKeys[] = [];
      let k = root;
      for (let i = 0; i < count; i++) {
        const s = secretsBlob.slice(i * EPOCH_SECRET_LEN, (i + 1) * EPOCH_SECRET_LEN);
        list.push(s);
        k = await stepKeys(k, s);
        derived.push(k);
      }
      const held = this.keys.get(this.cur.epoch);
      const again = derived.find((d) => d.epoch === this.cur.epoch);
      const agrees = !held || !again || confirmsEqual(held.confirm, again.confirm);
      if (this.dead || !agrees || !confirmsEqual(k.confirm, expectedConfirm)) return null;
      for (const s of this.secrets) s.fill(0);
      this.secrets = list;
      for (const d of derived) this.keys.set(d.epoch, d);
      this.cur = k;
      committed = true;
      return k;
    } finally {
      if (!committed) for (const s of list) s.fill(0);
    }
  }

  /// A copy of the secrets since the root, in order. The caller zeroes it.
  secretsBlob(): Uint8Array {
    const out = new Uint8Array(this.secrets.length * EPOCH_SECRET_LEN);
    this.secrets.forEach((s, i) => out.set(s, i * EPOCH_SECRET_LEN));
    return out;
  }

  wipe(): void {
    this.dead = true;
    for (const s of this.secrets) s.fill(0);
    this.secrets = [];
    this.keys.clear();
  }
}
