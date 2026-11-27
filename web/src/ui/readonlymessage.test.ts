// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import "monaco-editor/esm/vs/editor/contrib/readOnlyMessage/browser/contribution.js";
import { READ_ONLY_MESSAGE_CONTRIBUTION, silenceReadOnlyMessage } from "./readonlymessage";

/// Monaco's read-only message is rendered through its bundled DOMPurify,
/// which asks for a Trusted Types policy the page's CSP refuses. The fix
/// disposes that contribution by id, an internal name, so this pins it: a
/// Monaco upgrade that renames or reshapes it fails here.
function readOnlyEditor() {
  // jsdom has no matchMedia, and Monaco's theme service asks it about high
  // contrast when the first editor is made.
  if (typeof window.matchMedia !== "function") {
    window.matchMedia = ((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    })) as typeof window.matchMedia;
  }
  // Nor a 2D canvas, which Monaco reads the pixel ratio and font metrics from.
  HTMLCanvasElement.prototype.getContext = (() => ({
    measureText: (s: string) => ({ width: s.length * 8 }),
    font: "",
  })) as unknown as typeof HTMLCanvasElement.prototype.getContext;
  const host = document.createElement("div");
  document.body.appendChild(host);
  const model = monaco.editor.createModel("alpha", "markdown");
  const editor = monaco.editor.create(host, { model, readOnly: true });
  return { editor, model, host };
}

/// Watches the editor's message widget, the thing that renders the message.
function watchMessages(editor: monaco.editor.ICodeEditor) {
  const controller = editor.getContribution("editor.contrib.messageController") as unknown as
    | { showMessage: (...args: unknown[]) => void }
    | null;
  if (!controller) throw new Error("Monaco's message controller is not registered under the id this test expects");
  return vi.spyOn(controller, "showMessage").mockImplementation(() => {});
}

describe("Monaco's read-only message", () => {
  it("is shown on a read-only edit attempt when left alone", () => {
    const { editor, model } = readOnlyEditor();
    const shown = watchMessages(editor);
    try {
      expect(editor.getContribution(READ_ONLY_MESSAGE_CONTRIBUTION)).not.toBeNull();
      editor.trigger("keyboard", "type", { text: "x" });
      expect(shown).toHaveBeenCalledTimes(1);
      expect(model.getValue()).toBe("alpha");
    } finally {
      shown.mockRestore();
      editor.dispose();
      model.dispose();
    }
  });

  it("is never shown once silenced, and the editor stays read-only", () => {
    const { editor, model } = readOnlyEditor();
    const shown = watchMessages(editor);
    try {
      expect(silenceReadOnlyMessage(editor)).toBe(true);
      editor.trigger("keyboard", "type", { text: "x" });
      editor.updateOptions({ readOnly: false });
      editor.updateOptions({ readOnly: true });
      editor.trigger("keyboard", "type", { text: "y" });
      expect(shown).not.toHaveBeenCalled();
      expect(model.getValue()).toBe("alpha");
      // Moving and selecting are untouched.
      editor.setPosition({ lineNumber: 1, column: 1 });
      editor.trigger("keyboard", "cursorRight", null);
      expect(editor.getPosition()?.column).toBe(2);
      editor.trigger("keyboard", "editor.action.selectAll", null);
      expect(model.getValueInRange(editor.getSelection()!)).toBe("alpha");
    } finally {
      shown.mockRestore();
      editor.dispose();
      model.dispose();
    }
  });
});
