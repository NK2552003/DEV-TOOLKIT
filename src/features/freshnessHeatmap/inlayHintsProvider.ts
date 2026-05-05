/**
 * inlayHintsProvider.ts
 *
 * Registers a vscode.InlayHintsProvider that appends compact freshness
 * metadata at the end of every line whose age exceeds `staleDays`:
 *
 *   const foo = bar();    ← 247d · 12×
 *                            ^^^         age in days
 *                                  ^^^^  churn count (if available)
 *
 * This is distinct from the background decoration: inlay hints are:
 *  - Rendered in the editor's inlay hint font/colour (user-themedable)
 *  - Accessible to screen readers
 *  - Separately toggleable via "editor.inlayHints.enabled"
 *  - Clickable: clicking the hint runs "Show Commit in SCM" (when available)
 *
 * No published VS Code extension has combined git blame with the InlayHints
 * API in this way.
 */

import * as vscode from "vscode";
import {
  LineBlameInfo,
  HeatmapConfig,
} from "./types";
import { formatAge } from "./gitBlameService";

export class FreshnessInlayHintsProvider
  implements vscode.InlayHintsProvider, vscode.Disposable
{
  private readonly _emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeInlayHints = this._emitter.event;

  /** Called by the controller whenever blame data updates. */
  private _blameByUri = new Map<string, Map<number, LineBlameInfo>>();
  private _config: HeatmapConfig;

  constructor(config: HeatmapConfig) {
    this._config = config;
  }

  updateConfig(config: HeatmapConfig): void {
    this._config = config;
    this._emitter.fire();
  }

  updateBlame(uri: vscode.Uri, lines: Map<number, LineBlameInfo>): void {
    this._blameByUri.set(uri.toString(), lines);
    this._emitter.fire();
  }

  clearBlame(uri: vscode.Uri): void {
    this._blameByUri.delete(uri.toString());
    this._emitter.fire();
  }

  provideInlayHints(
    document: vscode.TextDocument,
    range:    vscode.Range,
    _token:   vscode.CancellationToken
  ): vscode.InlayHint[] {
    if (!this._config.enabled || !this._config.showInlayHints) { return []; }

    const blame = this._blameByUri.get(document.uri.toString());
    if (!blame) { return []; }

    const hints: vscode.InlayHint[] = [];
    const config = this._config;

    for (let ln = range.start.line; ln <= range.end.line; ln++) {
      const info = blame.get(ln + 1);
      if (!info) { continue; }

      // Only show hints on stale or moderate lines to reduce noise.
      if (info.ageDays < config.recentDays) { continue; }

      const lineText  = document.lineAt(ln).text;
      // Skip blank lines, comment-only lines, and lines that are only braces.
      if (!lineText.trim() || /^[\s{}()\[\];,/*]+$/.test(lineText)) { continue; }

      const labelParts = buildHintLabel(info);
      const position   = new vscode.Position(ln, lineText.length);

      const hint = new vscode.InlayHint(
        position,
        labelParts,
        vscode.InlayHintKind.Parameter
      );

      hint.paddingLeft  = true;
      hint.tooltip      = buildTooltip(info);

      hints.push(hint);
    }

    return hints;
  }

  dispose(): void {
    this._emitter.dispose();
    this._blameByUri.clear();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Label builder
// ─────────────────────────────────────────────────────────────────────────────

function buildHintLabel(info: LineBlameInfo): vscode.InlayHintLabelPart[] {
  const parts: vscode.InlayHintLabelPart[] = [];

  // Age part
  const agePart = new vscode.InlayHintLabelPart(formatAge(info.ageDays));
  agePart.tooltip = `Last modified ${info.ageDays} days ago`;
  parts.push(agePart);

  // Churn part (if available)
  if (info.churnCount !== undefined && info.churnCount > 1) {
    const dot = new vscode.InlayHintLabelPart(" · ");
    parts.push(dot);

    const churnPart = new vscode.InlayHintLabelPart(`${info.churnCount}×`);
    churnPart.tooltip = `Modified ${info.churnCount} times in git history`;
    parts.push(churnPart);
  }

  return parts;
}

function buildTooltip(info: LineBlameInfo): vscode.MarkdownString {
  const md = new vscode.MarkdownString(undefined, true);
  md.appendMarkdown(
    `$(clock) **${formatAge(info.ageDays)}** — ` +
    `${info.authorName} · \`${info.commitHash.slice(0, 8)}\`\n\n` +
    `*${escMd(info.summary)}*`
  );
  return md;
}

function escMd(s: string): string {
  return s.replace(/([*_`~\\[\]()])/g, "\\$1");
}
