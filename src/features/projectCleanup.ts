import * as vscode from "vscode";
import { createLogger } from "../utils/logger";
import { removeConsoleLogsFromEditor } from "./removeConsoleLogs";
import { removeUnusedImportsFromEditor } from "./removeUnusedImports";

const logger = createLogger("Dev Toolkit");

export function registerProjectCleanup(context: vscode.ExtensionContext) {
  const command = vscode.commands.registerCommand("devToolkit.projectCleanup", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("No active editor for project cleanup.");
      return;
    }

    const consoleCleanup = await removeConsoleLogsFromEditor(editor, {
      scope: "file",
      formatAfterCleanup: false
    });

    const importCleanup = await removeUnusedImportsFromEditor(editor);
    const trailingWhitespaceCleanup = await trimTrailingWhitespace(editor);

    const changedSteps: string[] = [];
    if (consoleCleanup.changed) {
      changedSteps.push("console.* statements");
    }
    if (importCleanup.changed) {
      changedSteps.push("unused imports");
    }
    if (trailingWhitespaceCleanup) {
      changedSteps.push("trailing whitespace");
    }

    if (changedSteps.length === 0) {
      vscode.window.showInformationMessage("Project cleanup complete. No issues found.");
      logger.info("ProjectCleanup", "No cleanup changes needed");
      return;
    }

    vscode.window.showInformationMessage(`Project cleanup complete: removed ${changedSteps.join(", ")}.`);
    logger.info("ProjectCleanup", `Updated ${editor.document.uri.fsPath}`);
  });

  context.subscriptions.push(command);
}

async function trimTrailingWhitespace(editor: vscode.TextEditor): Promise<boolean> {
  const beforeVersion = editor.document.version;

  try {
    await vscode.commands.executeCommand("editor.action.trimTrailingWhitespace");
  } catch {
    return false;
  }

  return editor.document.version !== beforeVersion;
}
