/**
 * types.ts — Complete type definitions for the enhanced Freshness Heatmap system.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Enumerations
// ─────────────────────────────────────────────────────────────────────────────

/** Visual mode the heatmap is operating in. */
export const enum HeatMode {
  Age    = "age",    // colour by last-modification date
  Churn  = "churn",  // colour by modification frequency
  Author = "author", // colour by contributor identity
}

/** Freshness tier for Age mode. */
export const enum FreshnessTier {
  Recent   = "recent",
  Moderate = "moderate",
  Stale    = "stale",
  Unknown  = "unknown",
}

/** Churn intensity tier for Churn mode. */
export const enum ChurnTier {
  Hot     = "hot",     // top 10 % of churn counts across file
  Warm    = "warm",    // next 40 %
  Cold    = "cold",    // bottom 50 %
  Unknown = "unknown",
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-line blame / churn payload
// ─────────────────────────────────────────────────────────────────────────────

/** Complete metadata for one editor line (1-indexed). */
export interface LineBlameInfo {
  lineNumber:   number;
  commitHash:   string;
  authorName:   string;
  authorEmail:  string;
  /** Unix seconds of author commit timestamp. */
  authorTime:   number;
  summary:      string;
  ageDays:      number;
  tier:         FreshnessTier;
  /** Populated after churn data is merged in. */
  churnTier?:   ChurnTier;
  churnCount?:  number;
  /** Index (0–7) into the file sparkline bucket array. */
  sparkBucket?: number;
  /** Hex tint assigned to this author for Author mode. */
  authorTint?:  string;
}

/** In-memory blame cache keyed on `"${filePath}::${headHash}"`. */
export interface BlameCache {
  headHash: string;
  lines:    Map<number, LineBlameInfo>;
  cachedAt: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sparkline data (file-level, 8-week history)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 8-week rolling commit-frequency histogram for one file.
 * Index 0 = oldest week, index 7 = current week.
 */
export interface FileSparklineData {
  weeklyBuckets: number[];
  peak:          number;
  totalCommits:  number;
  computedAt:    number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Churn data
// ─────────────────────────────────────────────────────────────────────────────

/** Per-line churn counts for a file (modification frequency). */
export interface FileChurnData {
  /** 1-based line number → count of distinct commits that modified it. */
  lineCounts:   Map<number, number>;
  /** All counts sorted ascending (for percentile thresholds). */
  sortedCounts: number[];
  computedAt:   number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Freshness score (per-file composite metric)
// ─────────────────────────────────────────────────────────────────────────────

export interface FreshnessScore {
  score:         number;  // 0–100
  recentPct:     number;
  moderatePct:   number;
  stalePct:      number;
  unknownPct:    number;
  avgAgeDays:    number;
  medianAgeDays: number;
  uniqueAuthors: number;
  grade:         "A" | "B" | "C" | "D" | "F";
  gradeLabel:    string;
  authors:       AuthorStats[];
}

/** Per-author contribution stats within a file. */
export interface AuthorStats {
  name:          string;
  email:         string;
  lineCount:     number;
  pct:           number;
  tint:          string;  // deterministic hex from email hash
  lastTouchDays: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace-level scan (used by Dashboard)
// ─────────────────────────────────────────────────────────────────────────────

export interface FileStaleness {
  fsPath:     string;
  relPath:    string;
  score:      number;
  grade:      string;
  avgAgeDays: number;
  stalePct:   number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface HeatmapConfig {
  enabled:             boolean;
  mode:                HeatMode;
  recentDays:          number;
  staleDays:           number;
  recentColor:         string;
  moderateColor:       string;
  staleColor:          string;
  opacity:             number;
  maxLines:            number;
  showStatusBar:       boolean;
  showSparklines:      boolean;
  showInlayHints:      boolean;
  showExplorerBadges:  boolean;
  showDiagnostics:     boolean;
  /** Lines older than this (days) get a zombie-code Diagnostic. Default 180. */
  zombieDays:          number;
}
