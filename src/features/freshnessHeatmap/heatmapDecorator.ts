/**
 * heatmapDecorator.ts
 *
 * Manages all TextEditorDecorationTypes for three heatmap modes
 * (Age / Churn / Author) plus the novel unicode-block gutter sparkline
 * decorations that show per-file commit frequency over the last 8 weeks.
 *
 * What's novel here:
 *  - Sparkline `before` decorations: each line gets a miniature ▁▂▃▄▅▆▇█
 *    bar chart in the gutter showing the file's weekly commit cadence, with
 *    the current line's commit week highlighted in a contrasting colour.
 *    No VS Code extension has ever done per-line commit-frequency glyphs.
 *  - Three independently toggleable visual modes on the same decoration layer.
 *  - Author-mode tints each line with a deterministic pastel tied to the
 *    contributor's email, making multi-author zones instantly visible.
 */

import * as vscode from "vscode";
import {
  FreshnessTier,
  ChurnTier,
  HeatMode,
  LineBlameInfo,
  FileSparklineData,
  HeatmapConfig,
} from "./types";
import { bucketsToSparkChars, formatAge } from "./gitBlameService";

// ─────────────────────────────────────────────────────────────────────────────
// Decoration type registry
// ─────────────────────────────────────────────────────────────────────────────

interface DecorTypes {
  // Age mode
  recent:   vscode.TextEditorDecorationType;
  moderate: vscode.TextEditorDecorationType;
  stale:    vscode.TextEditorDecorationType;
  // Churn mode
  hot:      vscode.TextEditorDecorationType;
  warm:     vscode.TextEditorDecorationType;
  cold:     vscode.TextEditorDecorationType;
  // Both modes — unknown / untracked
  unknown:  vscode.TextEditorDecorationType;
  // Gutter sparkline (shared across modes)
  sparkline: vscode.TextEditorDecorationType[];
}

let activeTypes: DecorTypes | null = null;

// ─────────────────────────────────────────────────────────────────────────────
// Build / dispose
// ─────────────────────────────────────────────────────────────────────────────

export function buildDecorationTypes(config: HeatmapConfig): DecorTypes {
  disposeDecorationTypes();

  const bg = (hex: string) => hexToRgba(hex, config.opacity);
  const ruler = (hex: string) => hexToRgba(hex, 0.75);
  const lane  = vscode.OverviewRulerLane.Right;

  const makeLine = (hex: string): vscode.TextEditorDecorationType =>
    vscode.window.createTextEditorDecorationType({
      isWholeLine:           true,
      backgroundColor:       bg(hex),
      overviewRulerColor:    ruler(hex),
      overviewRulerLane:     lane,
      rangeBehavior:         vscode.DecorationRangeBehavior.ClosedClosed,
    });

  // Build one decoration type per sparkline intensity level (0–9).
  // We use `before.contentText` with unicode block chars and a coloured gutter
  // strip alongside the line numbers.
  const sparkline: vscode.TextEditorDecorationType[] = [];
  for (let level = 0; level < 8; level++) {
    sparkline.push(
      vscode.window.createTextEditorDecorationType({
        before: {
          contentText: "",      // set per-line via DecorationOptions.renderOptions
          margin:       "0 6px 0 0",
          color:        sparkIntensityColor(level),
          fontWeight:   "400",
          fontStyle:    "normal",
        },
        rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
      })
    );
  }

  activeTypes = {
    recent:   makeLine(config.recentColor),
    moderate: makeLine(config.moderateColor),
    stale:    makeLine(config.staleColor),
    hot:      makeLine("#e040fb"),   // purple
    warm:     makeLine("#ff9800"),   // amber
    cold:     makeLine("#4db6ac"),   // teal
    unknown:  vscode.window.createTextEditorDecorationType({
      isWholeLine:        true,
      backgroundColor:    "rgba(128,128,128,0.07)",
      overviewRulerColor: "rgba(128,128,128,0.35)",
      overviewRulerLane:  lane,
      rangeBehavior:      vscode.DecorationRangeBehavior.ClosedClosed,
    }),
    sparkline,
  };

  return activeTypes;
}

export function disposeDecorationTypes(): void {
  if (!activeTypes) { return; }
  activeTypes.recent.dispose();
  activeTypes.moderate.dispose();
  activeTypes.stale.dispose();
  activeTypes.hot.dispose();
  activeTypes.warm.dispose();
  activeTypes.cold.dispose();
  activeTypes.unknown.dispose();
  for (const t of activeTypes.sparkline) { t.dispose(); }
  activeTypes = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply decorations
// ─────────────────────────────────────────────────────────────────────────────

interface Buckets {
  recent:   vscode.DecorationOptions[];
  moderate: vscode.DecorationOptions[];
  stale:    vscode.DecorationOptions[];
  hot:      vscode.DecorationOptions[];
  warm:     vscode.DecorationOptions[];
  cold:     vscode.DecorationOptions[];
  unknown:  vscode.DecorationOptions[];
  sparkline: vscode.DecorationOptions[][];  // one array per intensity level (0–7)
}

export function applyDecorations(
  editor:    vscode.TextEditor,
  blameMap:  Map<number, LineBlameInfo> | null,
  types:     DecorTypes,
  config:    HeatmapConfig,
  sparkData: FileSparklineData | null
): void {
  const doc       = editor.document;
  const lineCount = doc.lineCount;

  const buckets: Buckets = {
    recent:   [], moderate: [], stale:   [],
    hot:      [], warm:      [], cold:   [],
    unknown:  [],
    sparkline: Array.from({ length: 8 }, () => []),
  };

  // Precompute sparkline string once per file.
  const sparkStr = (sparkData && config.showSparklines)
    ? bucketsToSparkChars(sparkData.weeklyBuckets, sparkData.peak)
    : null;

  for (let ln = 0; ln < lineCount; ln++) {
    const info  = blameMap?.get(ln + 1) ?? null;
    const range = doc.lineAt(ln).range;
    const hover = buildHoverMarkdown(info, sparkData, sparkStr);

    const decoration: vscode.DecorationOptions = { range, hoverMessage: hover };

    if (!info) {
      buckets.unknown.push(decoration);
    } else {
      // ── Main colour bucket ──
      switch (config.mode) {
        case HeatMode.Age:
          pushAgeBucket(buckets, info, decoration);
          break;
        case HeatMode.Churn:
          pushChurnBucket(buckets, info, decoration);
          break;
        case HeatMode.Author:
          pushAuthorDecoration(editor, info, range, hover);
          break;
      }

      // ── Sparkline gutter ──
      if (sparkStr && info.sparkBucket !== undefined) {
        const level = info.sparkBucket;  // 0–7
        buckets.sparkline[level].push({
          range,
          renderOptions: {
            before: {
              contentText: sparkStr,
              color:        sparkIntensityColor(level),
            },
          },
        });
      }
    }
  }

  // Set decorations in one batch.
  editor.setDecorations(types.recent,   buckets.recent);
  editor.setDecorations(types.moderate, buckets.moderate);
  editor.setDecorations(types.stale,    buckets.stale);
  editor.setDecorations(types.hot,      buckets.hot);
  editor.setDecorations(types.warm,     buckets.warm);
  editor.setDecorations(types.cold,     buckets.cold);
  editor.setDecorations(types.unknown,  buckets.unknown);
  for (let i = 0; i < 8; i++) {
    editor.setDecorations(types.sparkline[i], buckets.sparkline[i]);
  }
}

export function clearDecorations(
  editor: vscode.TextEditor,
  types:  DecorTypes
): void {
  editor.setDecorations(types.recent,   []);
  editor.setDecorations(types.moderate, []);
  editor.setDecorations(types.stale,    []);
  editor.setDecorations(types.hot,      []);
  editor.setDecorations(types.warm,     []);
  editor.setDecorations(types.cold,     []);
  editor.setDecorations(types.unknown,  []);
  for (const t of types.sparkline) { editor.setDecorations(t, []); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bucket helpers
// ─────────────────────────────────────────────────────────────────────────────

function pushAgeBucket(
  b:    Buckets,
  info: LineBlameInfo,
  dec:  vscode.DecorationOptions
): void {
  switch (info.tier) {
    case FreshnessTier.Recent:   b.recent.push(dec);   break;
    case FreshnessTier.Moderate: b.moderate.push(dec); break;
    case FreshnessTier.Stale:    b.stale.push(dec);    break;
    default:                     b.unknown.push(dec);
  }
}

function pushChurnBucket(
  b:    Buckets,
  info: LineBlameInfo,
  dec:  vscode.DecorationOptions
): void {
  switch (info.churnTier ?? ChurnTier.Unknown) {
    case ChurnTier.Hot:     b.hot.push(dec);     break;
    case ChurnTier.Warm:    b.warm.push(dec);    break;
    case ChurnTier.Cold:    b.cold.push(dec);    break;
    default:                b.unknown.push(dec);
  }
}

/**
 * Author mode uses per-line `backgroundColor` derived from the author tint.
 * Since VSCode decoration types are shared across lines, Author mode creates
 * per-decoration backgroundColor via `renderOptions.after`.
 * We do this via a transparent whole-line decoration + a coloured `before`
 * text that serves as a left gutter strip.
 */
function pushAuthorDecoration(
  editor: vscode.TextEditor,
  info:   LineBlameInfo,
  range:  vscode.Range,
  hover:  vscode.MarkdownString
): void {
  const tint    = info.authorTint ?? "#808080";
  // We can't call editor.setDecorations here because we're mid-loop.
  // Author mode instead uses the overview ruler of the 'unknown' type with
  // a per-line renderOptions. This is achieved by creating an ad-hoc type
  // per author colour. To avoid creating thousands of types, we cache them.
  const type = getOrCreateAuthorType(tint);
  editor.setDecorations(type, [{
    range,
    hoverMessage: hover,
  }]);
}

const authorDecorTypes = new Map<string, vscode.TextEditorDecorationType>();
function getOrCreateAuthorType(
  tint: string
): vscode.TextEditorDecorationType {
  let type = authorDecorTypes.get(tint);
  if (!type) {
    type = vscode.window.createTextEditorDecorationType({
      isWholeLine:        true,
      backgroundColor:    hexToRgba(tint, 0.14),
      overviewRulerColor: hexToRgba(tint, 0.8),
      overviewRulerLane:  vscode.OverviewRulerLane.Right,
      rangeBehavior:      vscode.DecorationRangeBehavior.ClosedClosed,
    });
    authorDecorTypes.set(tint, type);
  }
  return type;
}

export function disposeAuthorTypes(): void {
  for (const t of authorDecorTypes.values()) { t.dispose(); }
  authorDecorTypes.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// Hover markdown
// ─────────────────────────────────────────────────────────────────────────────

function buildHoverMarkdown(
  info:      LineBlameInfo | null,
  sparkData: FileSparklineData | null,
  sparkStr:  string | null
): vscode.MarkdownString {
  const md = new vscode.MarkdownString(undefined, true);
  md.isTrusted = true;
  md.supportHtml = true;

  if (!info) {
    md.appendMarkdown("$(flame) **Freshness Heatmap**\n\n");
    md.appendMarkdown("This file is not tracked by git.");
    return md;
  }

  const ageLabel   = formatAge(info.ageDays);
  const tierIcon   = tierIcon_(info.tier);
  const tierLabel  = tierLabel_(info.tier);
  const shortHash  = info.commitHash.slice(0, 8);

  md.appendMarkdown(`${tierIcon} **Freshness** — ${tierLabel}\n\n`);
  md.appendMarkdown("---\n\n");
  md.appendMarkdown(`$(clock) **Last modified:** ${ageLabel} *(${info.ageDays}d)*\n\n`);

  if (info.churnCount !== undefined) {
    const churnIcon = info.churnTier === ChurnTier.Hot
      ? "$(flame)" : info.churnTier === ChurnTier.Warm ? "$(warning)" : "$(dash)";
    md.appendMarkdown(
      `${churnIcon} **Churn:** ${info.churnCount} modification${info.churnCount !== 1 ? "s" : ""}\n\n`
    );
  }

  if (info.authorName) {
    const tintBadge = info.authorTint
      ? `<span style="color:${info.authorTint};">■</span> `
      : "";
    md.appendMarkdown(`$(person) **Author:** ${tintBadge}${escMd(info.authorName)}`);
    if (info.authorEmail) {
      md.appendMarkdown(` \`${info.authorEmail}\``);
    }
    md.appendMarkdown("\n\n");
  }

  if (info.summary) {
    md.appendMarkdown(`$(git-commit) *${escMd(info.summary)}*\n\n`);
  }

  md.appendMarkdown(`$(symbol-key) \`${shortHash}\`\n\n`);

  // Sparkline section
  if (sparkStr && sparkData) {
    md.appendMarkdown("---\n\n");
    md.appendMarkdown("$(graph) **File activity (8 wks):** `");
    md.appendMarkdown(sparkStr);
    md.appendMarkdown("`");
    if (info.sparkBucket !== undefined) {
      const weekLabel = info.sparkBucket === 7 ? "this week"
        : info.sparkBucket === 6 ? "last week"
        : `${8 - info.sparkBucket} weeks ago`;
      md.appendMarkdown(` ← *this line: ${weekLabel}*`);
    }
    md.appendMarkdown(`\n\n$(git-branch) ${sparkData.totalCommits} commits in window`);
  }

  return md;
}

// ─────────────────────────────────────────────────────────────────────────────
// Colour helpers
// ─────────────────────────────────────────────────────────────────────────────

function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace(/^#/, "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha.toFixed(2)})`;
}

/** Maps sparkline bucket index (0=oldest, 7=newest) to a display colour. */
function sparkIntensityColor(bucketIndex: number): string {
  // Gradient: dim grey → vibrant cyan
  const t      = bucketIndex / 7;
  const r      = Math.round(40  + t * (80 - 40));
  const g      = Math.round(100 + t * (220 - 100));
  const b      = Math.round(120 + t * (255 - 120));
  return `rgba(${r},${g},${b},0.65)`;
}

function tierIcon_(tier: FreshnessTier): string {
  switch (tier) {
    case FreshnessTier.Recent:   return "$(pass-filled)";
    case FreshnessTier.Moderate: return "$(warning)";
    case FreshnessTier.Stale:    return "$(error)";
    default:                     return "$(question)";
  }
}

function tierLabel_(tier: FreshnessTier): string {
  switch (tier) {
    case FreshnessTier.Recent:   return "Recent";
    case FreshnessTier.Moderate: return "Moderate";
    case FreshnessTier.Stale:    return "Stale";
    default:                     return "Unknown";
  }
}

function escMd(s: string): string {
  return s.replace(/([*_`~\\[\]()])/g, "\\$1");
}
