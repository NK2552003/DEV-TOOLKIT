/**
 * freshnessScoreService.ts
 *
 * Computes a composite Freshness Score (0–100) for any file that has
 * been blame-analysed.  The score feeds:
 *  - The status-bar grade badge  (A–F)
 *  - The Webview Dashboard ranking panel
 *  - The Diagnostic "zombie code" warnings
 *  - The file-explorer badge decoration
 *
 * Scoring model (weighted sum, normalised to 100):
 *   40 pts  — recency   : percentage of lines in "recent" tier
 *   30 pts  — freshness : inverted avg-age-days (capped at staleDays × 2)
 *   20 pts  — coverage  : what fraction of lines have real blame data
 *   10 pts  — momentum  : whether file was touched in last 7 days at all
 */

import {
  LineBlameInfo,
  FreshnessTier,
  FreshnessScore,
  AuthorStats,
  HeatmapConfig,
} from "./types";

// ─────────────────────────────────────────────────────────────────────────────
// Public
// ─────────────────────────────────────────────────────────────────────────────

export function computeFreshnessScore(
  lines:  Map<number, LineBlameInfo>,
  config: HeatmapConfig
): FreshnessScore {
  if (lines.size === 0) {
    return emptyScore();
  }

  const all        = [...lines.values()];
  const known      = all.filter(l => l.tier !== FreshnessTier.Unknown);
  const recentPct  = pct(all, l => l.tier === FreshnessTier.Recent);
  const modPct     = pct(all, l => l.tier === FreshnessTier.Moderate);
  const stalePct   = pct(all, l => l.tier === FreshnessTier.Stale);
  const unknownPct = pct(all, l => l.tier === FreshnessTier.Unknown);

  const ages    = known.map(l => l.ageDays);
  const avgAge  = ages.length ? ages.reduce((a, b) => a + b, 0) / ages.length : 0;
  const medAge  = ages.length ? median(ages) : 0;

  // Component scores
  const recencyScore  = recentPct * 40;
  const cap           = config.staleDays * 2;
  const ageNorm       = Math.max(0, 1 - avgAge / cap);
  const freshnessScore = ageNorm * 30;
  const coveragePct   = known.length / Math.max(all.length, 1);
  const coverageScore = coveragePct * 20;
  const hasMomentum   = all.some(l => l.ageDays < 7);
  const momentumScore = hasMomentum ? 10 : 0;

  const raw   = recencyScore + freshnessScore + coverageScore + momentumScore;
  const score = Math.min(100, Math.max(0, Math.round(raw)));

  // Author breakdown
  const authorMap = new Map<string, AuthorStats>();
  for (const l of all) {
    const key = l.authorEmail || l.authorName;
    const existing = authorMap.get(key);
    if (!existing) {
      authorMap.set(key, {
        name:          l.authorName,
        email:         l.authorEmail,
        lineCount:     1,
        pct:           0,
        tint:          l.authorTint ?? "#808080",
        lastTouchDays: l.ageDays,
      });
    } else {
      existing.lineCount++;
      if (l.ageDays < existing.lastTouchDays) {
        existing.lastTouchDays = l.ageDays;
      }
    }
  }

  const authors: AuthorStats[] = [...authorMap.values()]
    .map(a => ({ ...a, pct: (a.lineCount / all.length) * 100 }))
    .sort((a, b) => b.lineCount - a.lineCount);

  const grade = scoreToGrade(score);

  return {
    score,
    recentPct:     recentPct  * 100,
    moderatePct:   modPct     * 100,
    stalePct:      stalePct   * 100,
    unknownPct:    unknownPct * 100,
    avgAgeDays:    Math.round(avgAge),
    medianAgeDays: Math.round(medAge),
    uniqueAuthors: authors.length,
    grade,
    gradeLabel:    gradeLabel(grade),
    authors,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function pct(arr: LineBlameInfo[], pred: (l: LineBlameInfo) => boolean): number {
  if (arr.length === 0) { return 0; }
  return arr.filter(pred).length / arr.length;
}

function median(nums: number[]): number {
  const sorted = [...nums].sort((a, b) => a - b);
  const mid    = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function scoreToGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 80) { return "A"; }
  if (score >= 65) { return "B"; }
  if (score >= 50) { return "C"; }
  if (score >= 35) { return "D"; }
  return "F";
}

function gradeLabel(grade: string): string {
  switch (grade) {
    case "A": return "Pristine — actively maintained";
    case "B": return "Healthy — mostly fresh";
    case "C": return "Ageing — needs attention";
    case "D": return "Stale — refactoring advised";
    case "F": return "Zombie — critical tech debt";
    default:  return "";
  }
}

function emptyScore(): FreshnessScore {
  return {
    score: 0, recentPct: 0, moderatePct: 0, stalePct: 0, unknownPct: 100,
    avgAgeDays: 0, medianAgeDays: 0, uniqueAuthors: 0,
    grade: "F", gradeLabel: "No data", authors: [],
  };
}
