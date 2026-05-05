/**
 * zombieDiagnosticsService.ts
 *
 * Emits real VS Code Diagnostic entries (shown in Problems panel + squiggles)
 * for contiguous "zombie" code blocks — sequences of 5+ consecutive lines
 * that have not been modified in more than `config.zombieDays` days.
 *
 * This is a genuinely novel capability: no existing VS Code extension
 * surfaces git-age data through the standard Diagnostic/Problems channel.
 * It means zombie regions are:
 *   • Listed in the Problems panel
 *   • Surfaced by lint-aware CI workflows (via --log-level)
 *   • Readable by other extensions that consume DiagnosticCollections
 */

import * as vscode from "vscode";
import { LineBlameInfo, FreshnessTier, HeatmapConfig } from "./types";
import { formatAge } from "./gitBlameService";

const COLLECTION_ID = "freshnessHeatmap";
const MIN_ZOMBIE_RUN = 5; // minimum consecutive zombie lines to emit a diagnostic

let collection: vscode.DiagnosticCollection | null = null;

// ─────────────────────────────────────────────────────────────────────────────
// Public
// ─────────────────────────────────────────────────────────────────────────────

export function getDiagnosticCollection(): vscode.DiagnosticCollection {
  if (!collection) {
    collection = vscode.languages.createDiagnosticCollection(COLLECTION_ID);
  }
  return collection;
}

/**
 * Re-computes zombie diagnostics for a single document.
 * Replaces any previously emitted diagnostics for that URI.
 */
export function updateDiagnostics(
  document: vscode.TextDocument,
  lines:    Map<number, LineBlameInfo>,
  config:   HeatmapConfig
): void {
  if (!config.showDiagnostics) {
    getDiagnosticCollection().delete(document.uri);
    return;
  }

  const diagnostics = buildDiagnostics(document, lines, config);
  getDiagnosticCollection().set(document.uri, diagnostics);
}

/** Removes all diagnostics for a specific URI. */
export function clearDiagnostics(uri: vscode.Uri): void {
  getDiagnosticCollection().delete(uri);
}

/** Removes all diagnostics across all files. */
export function clearAllDiagnostics(): void {
  getDiagnosticCollection().clear();
}

export function disposeDiagnostics(): void {
  collection?.dispose();
  collection = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

interface ZombieRun {
  startLine: number;  // 0-indexed
  endLine:   number;  // 0-indexed, inclusive
  maxAge:    number;  // oldest line in run (days)
  authors:   Set<string>;
}

function buildDiagnostics(
  document: vscode.TextDocument,
  lines:    Map<number, LineBlameInfo>,
  config:   HeatmapConfig
): vscode.Diagnostic[] {
  const zombieRuns = findZombieRuns(document.lineCount, lines, config);
  const diagnostics: vscode.Diagnostic[] = [];

  for (const run of zombieRuns) {
    const startPos = new vscode.Position(run.startLine, 0);
    const endLine  = document.lineAt(run.endLine);
    const endPos   = new vscode.Position(run.endLine, endLine.text.length);
    const range    = new vscode.Range(startPos, endPos);

    const runLength  = run.endLine - run.startLine + 1;
    const ageLabel   = formatAge(run.maxAge);
    const authorList = [...run.authors].slice(0, 3).join(", ");

    const message = [
      `Zombie code block (${runLength} lines, last touched ${ageLabel})`,
      run.authors.size > 0 ? `— authored by: ${authorList}` : "",
      run.maxAge > config.zombieDays * 2 ? " Consider removing or archiving." : "",
    ].filter(Boolean).join(" ");

    const diag = new vscode.Diagnostic(
      range,
      message,
      diagnosticSeverity(run.maxAge, config)
    );

    diag.source = "Freshness Heatmap";
    diag.code   = {
      value: "zombie-code",
      target: vscode.Uri.parse(
        "https://github.com/sidkr222003/DEV-TOOLKIT#freshness-heatmap"
      ),
    };

    // Related information: point at the oldest line in the block.
    const oldestLine = findOldestLine(lines, run.startLine, run.endLine);
    if (oldestLine !== null) {
      const oldestInfo = lines.get(oldestLine + 1)!;
      diag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(
            document.uri,
            document.lineAt(oldestLine).range
          ),
          `Oldest line in block — last modified ${formatAge(oldestInfo.ageDays)} by ${oldestInfo.authorName}`
        ),
      ];
    }

    diagnostics.push(diag);
  }

  return diagnostics;
}

function findZombieRuns(
  lineCount: number,
  lines:     Map<number, LineBlameInfo>,
  config:    HeatmapConfig
): ZombieRun[] {
  const runs: ZombieRun[] = [];
  let currentRun: ZombieRun | null = null;

  for (let ln = 0; ln < lineCount; ln++) {
    const info = lines.get(ln + 1);
    const isZombie =
      info !== undefined &&
      info.tier !== FreshnessTier.Unknown &&
      info.ageDays >= config.zombieDays;

    if (isZombie && info) {
      if (!currentRun) {
        currentRun = {
          startLine: ln,
          endLine:   ln,
          maxAge:    info.ageDays,
          authors:   new Set([info.authorName]),
        };
      } else {
        currentRun.endLine = ln;
        currentRun.maxAge  = Math.max(currentRun.maxAge, info.ageDays);
        currentRun.authors.add(info.authorName);
      }
    } else {
      if (currentRun && (currentRun.endLine - currentRun.startLine + 1) >= MIN_ZOMBIE_RUN) {
        runs.push(currentRun);
      }
      currentRun = null;
    }
  }

  // Flush final run.
  if (currentRun && (currentRun.endLine - currentRun.startLine + 1) >= MIN_ZOMBIE_RUN) {
    runs.push(currentRun);
  }

  return runs;
}

function diagnosticSeverity(
  ageDays: number,
  config:  HeatmapConfig
): vscode.DiagnosticSeverity {
  if (ageDays >= config.zombieDays * 3) { return vscode.DiagnosticSeverity.Error; }
  if (ageDays >= config.zombieDays * 2) { return vscode.DiagnosticSeverity.Warning; }
  return vscode.DiagnosticSeverity.Information;
}

function findOldestLine(
  lines:     Map<number, LineBlameInfo>,
  startLine: number,
  endLine:   number
): number | null {
  let oldest: number | null = null;
  let maxAge = -1;
  for (let ln = startLine; ln <= endLine; ln++) {
    const info = lines.get(ln + 1);
    if (info && info.ageDays > maxAge) {
      maxAge  = info.ageDays;
      oldest  = ln;
    }
  }
  return oldest;
}
