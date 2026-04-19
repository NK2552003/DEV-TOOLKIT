import * as vscode from "vscode";
import { registerFileSize } from "./features/fileSize";
import { registerExplorerSizeDecorations } from "./features/explorerSizeDecorations";
import { registerRemoveConsoleLogs } from "./features/removeConsoleLogs";
import { registerReadTime } from "./features/readTime";
import { registerCodeExplainer } from "./features/codeExplainer";
import { registerFunctionReferences } from "./features/functionReferences";
import { registerCodeStyleMood } from "./features/codeStyleMood";

export function activate(context: vscode.ExtensionContext) {
  registerFileSize(context);
  registerExplorerSizeDecorations(context);
  registerRemoveConsoleLogs(context);
  registerReadTime(context);
  registerCodeExplainer(context);
  registerFunctionReferences(context);
  registerCodeStyleMood(context);
}

export function deactivate(): void {}
