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

  has(epoch: number): boolean {
    return this.keys.has(epoch);
  }

  keyFor(epoch: number): CryptoKey | null {
    return this.keys.get(epoch)?.contentKey ?? null;
  }

  /// Commit a step, but only if it is the next epoch and what it derives
  /// matches the confirmation the rotator sent. Otherwise nothing changes.
  async applyStep(to: number, secret: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    if (to !== this.cur.epoch + 1 || secret.length !== EPOCH_SECRET_LEN) return null;
    const next = await stepKeys(this.cur, secret);
    if (!confirmsEqual(next.confirm, expectedConfirm)) return null;
    this.secrets.push(secret.slice());
    this.keys.set(next.epoch, next);
    this.cur = next;
    return next;
  }

  /// Catch up from the root with the secrets a member handed over.
  async applyHandover(to: number, secretsBlob: Uint8Array, expectedConfirm: Uint8Array): Promise<EpochKeys | null> {
    const count = to - this.rootEpoch;
    if (to <= this.cur.epoch || count <= 0 || secretsBlob.length !== count * EPOCH_SECRET_LEN) return null;
    const root = this.keys.get(this.rootEpoch);
    if (!root) return null;
    const list: Uint8Array[] = [];
    const derived: EpochKeys[] = [];
    let k = root;
    for (let i = 0; i < count; i++) {
      const s = secretsBlob.slice(i * EPOCH_SECRET_LEN, (i + 1) * EPOCH_SECRET_LEN);
      k = await stepKeys(k, s);
      list.push(s);
      derived.push(k);
    }
    const held = this.keys.get(this.cur.epoch);
    const again = derived.find((d) => d.epoch === this.cur.epoch);
    const agrees = !held || !again || confirmsEqual(held.confirm, again.confirm);
    if (!agrees || !confirmsEqual(k.confirm, expectedConfirm)) {
      for (const s of list) s.fill(0);
      return null;
    }
    for (const s of this.secrets) s.fill(0);
    this.secrets = list;
    for (const d of derived) this.keys.set(d.epoch, d);
    this.cur = k;
    return k;
  }

  /// A copy of the secrets since the root, in order. The caller zeroes it.
  secretsBlob(): Uint8Array {
    const out = new Uint8Array(this.secrets.length * EPOCH_SECRET_LEN);
    this.secrets.forEach((s, i) => out.set(s, i * EPOCH_SECRET_LEN));
    return out;
  }

  wipe(): void {
    for (const s of this.secrets) s.fill(0);
    this.secrets = [];
    this.keys.clear();
  }
}
