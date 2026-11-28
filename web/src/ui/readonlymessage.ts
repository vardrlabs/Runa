import type { editor as MonacoEditor } from "monaco-editor";

/// The id Monaco registers its "Cannot edit in read-only editor" contribution
/// under (monaco-editor 0.52.2:
/// esm/vs/editor/contrib/readOnlyMessage/browser/contribution.js,
/// ReadOnlyMessageController).
export const READ_ONLY_MESSAGE_CONTRIBUTION = "editor.contrib.readOnlyMessageController";

/// Stops Monaco from answering typing in a read-only editor with its own
/// "Cannot edit in read-only editor" message.
///
/// That message is rendered as markdown, and Monaco's markdown renderer runs
/// its bundled DOMPurify, which asks for a Trusted Types policy named
/// "dompurify". The page's CSP does not allow that name, and is not meant to,
/// so every keystroke in a read-only tab reported a CSP violation. The page
/// already says why the editor is read-only: the banner on a removed or
/// left-out tab, and the countdown while a room burns.
///
/// It disposes only the contribution that listens for read-only edit
/// attempts. Selecting, copying, moving the cursor and Find are other
/// contributions and keep working. It is done once, when the editor mounts,
/// so it holds for every read-only state the editor later enters, and an
/// editable editor never fires the event anyway.
///
/// On a Monaco upgrade, recheck that the contribution still has this id and
/// still renders through the markdown renderer. readonlymessage.test.ts fails
/// if the id stops resolving, and the browser e2e's typing step on a removed
/// tab fails if the message comes back by another route.
///
/// Returns whether the contribution was found and disposed.
export function silenceReadOnlyMessage(editor: MonacoEditor.ICodeEditor): boolean {
  const contribution = editor.getContribution(READ_ONLY_MESSAGE_CONTRIBUTION);
  if (!contribution) return false;
  contribution.dispose();
  return true;
}
