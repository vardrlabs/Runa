// @vitest-environment jsdom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { EvictModal } from "./EvictModal";

/// Where focus goes in the dialog that asks the room to remove someone or
/// change the link (amendment K). jsdom lays nothing out, so every element is
/// treated as on screen here.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "getClientRects", {
    configurable: true,
    value: () => [{ width: 1, height: 1 }],
  });
});

let root: Root | null = null;

afterEach(() => {
  if (root) act(() => root!.unmount());
  root = null;
  document.body.innerHTML = "";
});

/// What the dialog asked the page to do.
let calls: string[] = [];

function render(
  state: string,
  returnFocus?: () => HTMLElement | null,
  onPropose: () => Promise<string | null> = async () => null,
): (next: string) => void {
  calls = [];
  const container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  const draw = (s: string) =>
    act(() =>
      root!.render(
        createElement(EvictModal, {
          candidates: [],
          relink: true,
          wayKind: "link",
          state: s,
          returnFocus,
          onPropose,
          onClose: () => calls.push("close"),
          onWithdraw: () => calls.push("withdraw"),
        }),
      ),
    );
  draw(state);
  return draw;
}

const button = (label: string) => [...document.querySelectorAll("button")].find((b) => b.textContent === label);
const cancelButton = () => button("Cancel")!;
const dialog = () => document.querySelector('[role="dialog"]') as HTMLElement;
const escape = () => act(() => void dialog().dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })));

describe("the remove-someone dialog's focus", () => {
  it("does not count the page body as the control that opened it, and gives focus to the fallback (review M-4)", () => {
    const fallback = document.createElement("button");
    document.body.appendChild(fallback);
    (document.activeElement as HTMLElement | null)?.blur();
    expect(document.activeElement).toBe(document.body);
    render("IDLE", () => fallback);
    expect(document.activeElement).toBe(cancelButton());
    act(() => root!.unmount());
    root = null;
    expect(document.activeElement).toBe(fallback);
  });

  it("moves focus off the request button to Cancel once the button is disabled by a vote in flight (review M-5)", () => {
    const draw = render("IDLE");
    const propose = document.getElementById("evict-propose") as HTMLButtonElement;
    propose.focus();
    expect(document.activeElement).toBe(propose);
    draw("VOTING");
    expect(propose.disabled).toBe(true);
    expect(document.activeElement).toBe(document.getElementById("evict-close"));
  });
});

describe("the ask dialog while this tab's own request is open (fourth final wave, I2)", () => {
  it("closes without withdrawing, from Close and from Escape, and withdraws only from Withdraw request", () => {
    render("VOTING");
    const close = document.getElementById("evict-close") as HTMLButtonElement;
    const withdraw = document.getElementById("evict-withdraw") as HTMLButtonElement;
    expect(close.textContent).toBe("Close");
    expect(withdraw.textContent).toBe("Withdraw request");
    expect(button("Cancel")).toBeUndefined();
    act(() => close.click());
    expect(calls).toEqual(["close"]);
    escape();
    expect(calls).toEqual(["close", "close"]);
    act(() => withdraw.click());
    expect(calls).toEqual(["close", "close", "withdraw"]);
  });

  it("offers no withdrawal once everyone agreed, and Close still only closes", () => {
    render("APPROVED");
    expect(document.getElementById("evict-withdraw")).toBeNull();
    act(() => (document.getElementById("evict-close") as HTMLButtonElement).click());
    expect(calls).toEqual(["close"]);
  });

  it("offers Cancel and no withdrawal before anything was asked, and once the request ended", () => {
    for (const state of ["IDLE", "REJECTED"]) {
      render(state);
      expect(document.getElementById("evict-withdraw")).toBeNull();
      act(() => cancelButton().click());
      escape();
      expect(calls).toEqual(["close", "close"]);
      act(() => root!.unmount());
      root = null;
    }
  });

  it("cannot be closed or withdrawn while the keys are made, and offers both once the request has gone out", async () => {
    let finish: (code: string | null) => void = () => {};
    const draw = render("IDLE", undefined, () => new Promise((r) => (finish = r)));
    act(() => (document.getElementById("evict-propose") as HTMLButtonElement).click());
    expect(dialog().getAttribute("aria-busy")).toBe("true");
    expect(cancelButton().disabled).toBe(true);
    expect(document.getElementById("evict-withdraw")).toBeNull();
    act(() => cancelButton().click());
    escape();
    expect(calls).toEqual([]);
    draw("VOTING");
    expect(document.getElementById("evict-withdraw")).toBeNull();
    expect((document.getElementById("evict-close") as HTMLButtonElement).disabled).toBe(true);
    await act(async () => finish(null));
    expect(dialog().getAttribute("aria-busy")).toBe("false");
    expect((document.getElementById("evict-close") as HTMLButtonElement).disabled).toBe(false);
    expect(document.getElementById("evict-withdraw")).not.toBeNull();
  });

  it("tells the person whose own request ran out that the others may have set it aside (M3)", () => {
    render("EXPIRED");
    expect(dialog().textContent).toMatch(/eight requests were already open in this room or you have one open in another tab/);
  });
});

describe("the ask dialog in a shared room", () => {
  it("clears the typed passphrase whichever way the dialog closes", () => {
    const container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    calls = [];
    const draw = (state: string) =>
      act(() =>
        root!.render(
          createElement(EvictModal, {
            candidates: [],
            relink: true,
            wayKind: "pass",
            state,
            onPropose: async () => null,
            onClose: () => calls.push("close"),
            onWithdraw: () => calls.push("withdraw"),
          }),
        ),
      );
    draw("IDLE");
    const field = document.getElementById("evict-passphrase") as HTMLInputElement;
    expect(field).not.toBeNull();
    const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    act(() => {
      setValue.call(field, "a typed passphrase");
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(field.value).toBe("a typed passphrase");
    act(() => cancelButton().click());
    expect(calls).toEqual(["close"]);
    expect(field.value).toBe("");
  });
});
