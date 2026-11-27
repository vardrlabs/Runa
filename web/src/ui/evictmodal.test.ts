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

function render(state: string, returnFocus?: () => HTMLElement | null): (next: string) => void {
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
          onPropose: async () => null,
          onCancel: () => {},
        }),
      ),
    );
  draw(state);
  return draw;
}

const cancelButton = () => [...document.querySelectorAll("button")].find((b) => b.textContent === "Cancel")!;

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
    expect(document.activeElement).toBe(cancelButton());
  });
});
