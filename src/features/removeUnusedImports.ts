import * as vscode from "vscode";
import { createLogger } from "../utils/logger";

const logger = createLogger("Dev Toolkit");

export interface RemoveUnusedImportsResult {
  changed: boolean;
  method: "source.removeUnusedImports" | "organizeImports" | "none";
}

export function registerRemoveUnusedImports(context: vscode.ExtensionContext) {
  const command = vscode.commands.registerCommand("devToolkit.removeUnusedImports", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("No active editor to remove unused imports from.");
      return;
    }

    const result = await removeUnusedImportsFromEditor(editor);
    if (!result.changed) {
      vscode.window.showInformationMessage("No unused imports found.");
      return;
    }

    vscode.window.showInformationMessage("Removed unused imports.");
    logger.info("RemoveUnusedImports", `Applied via ${result.method}`);
  });

  context.subscriptions.push(command);
}

export async function removeUnusedImportsFromEditor(editor: vscode.TextEditor): Promise<RemoveUnusedImportsResult> {
  const beforeVersion = editor.document.version;
  let removeUnusedImportsUnavailable = false;

  try {
    await vscode.commands.executeCommand("editor.action.codeAction", {
      kind: "source.removeUnusedImports",
      apply: "first"
    });
  } catch {
    // Fall back to organize imports only when removeUnusedImports is unavailable.
    removeUnusedImportsUnavailable = true;
  }

  if (editor.document.version !== beforeVersion) {
    return { changed: true, method: "source.removeUnusedImports" };
  }

  if (!removeUnusedImportsUnavailable) {
    return { changed: false, method: "none" };
  }

  try {
    await vscode.commands.executeCommand("editor.action.organizeImports");
  } catch {
    return { changed: false, method: "none" };
  }

  if (editor.document.version !== beforeVersion) {
    return { changed: true, method: "organizeImports" };
  }

  return { changed: false, method: "none" };
}
