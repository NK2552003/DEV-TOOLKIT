/**
 * gitBlameService.ts
 *
 * Runs `git blame --line-porcelain`, parses per-line blame info,
 * fetches the 8-week commit-frequency sparkline for the file,
 * merges sparkBucket into each LineBlameInfo, and caches results
 * keyed on filePath × HEAD hash.
 */

import { exec }        from "child_process";
import * as path       from "path";
import * as util       from "util";
import {
  FreshnessTier,
  LineBlameInfo,
  BlameCache,
  FileSparklineData,
  HeatmapConfig,
} from "./types";

const execAsync = util.promisify(exec);
const GIT_MAX_BUFFER = 10 * 1024 * 1024; // 10 MB

// ─────────────────────────────────────────────────────────────────────────────
// Caches
// ─────────────────────────────────────────────────────────────────────────────

const blameCache     = new Map<string, BlameCache>();
const sparklineCache = new Map<string, FileSparklineData>();
const inflight       = new Map<string, Promise<BlameCache | null>>();

// Author tint palette (deterministic, accessible colours).
const AUTHOR_TINTS = [
  "#5c9eff", "#ff7b54", "#54d17a", "#e27cff",
  "#ffd95c", "#54d6ff", "#ff5454", "#b8ff54",
  "#ff54b8", "#54ffec",
];
const authorTintMap = new Map<string, string>();

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

export async function getBlameForFile(
  filePath:      string,
  workspaceRoot: string,
  config:        HeatmapConfig
): Promise<BlameCache | null> {
  const normalized = path.normalize(filePath);
  const cacheKey   = await buildCacheKey(normalized, workspaceRoot);
  if (!cacheKey) { return null; }

  const cached = blameCache.get(cacheKey);
  if (cached) { return cached; }

  const existing = inflight.get(cacheKey);
  if (existing) { return existing; }

  const promise = runBlame(normalized, workspaceRoot, cacheKey, config);
  inflight.set(cacheKey, promise);
  promise.finally(() => inflight.delete(cacheKey));
  return promise;
}

export async function getSparklineForFile(
  filePath:      string,
  workspaceRoot: string
): Promise<FileSparklineData | null> {
  const normalized = path.normalize(filePath);
  const relPath    = path.relative(workspaceRoot, normalized);
  const cacheKey   = `spark::${normalized}`;

  const cached = sparklineCache.get(cacheKey);
  // Sparkline data valid for 30 minutes.
  if (cached && Date.now() - cached.computedAt < 30 * 60 * 1000) {
    return cached;
  }

  try {
    const { stdout } = await execAsync(
      `git log --format="%ai" -- "${relPath}"`,
      { cwd: workspaceRoot, maxBuffer: GIT_MAX_BUFFER }
    );

    const data = computeSparkline(stdout);
    sparklineCache.set(cacheKey, data);
    return data;
  } catch {
    return null;
  }
}

export function invalidateFile(filePath: string): void {
  const normalized = path.normalize(filePath);
  for (const key of blameCache.keys()) {
    if (key.startsWith(normalized + "::")) { blameCache.delete(key); }
  }
  sparklineCache.delete(`spark::${normalized}`);
}

export function clearCache(): void {
  blameCache.clear();
  sparklineCache.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// Core blame runner
// ─────────────────────────────────────────────────────────────────────────────

async function buildCacheKey(
  filePath: string,
  cwd:      string
): Promise<string | null> {
  try {
    const { stdout } = await execAsync("git rev-parse HEAD", {
      cwd, maxBuffer: 1024,
    });
    return `${filePath}::${stdout.trim()}`;
  } catch {
    return null;
  }
}

async function runBlame(
  filePath:      string,
  workspaceRoot: string,
  cacheKey:      string,
  config:        HeatmapConfig
): Promise<BlameCache | null> {
  try {
    const headHash = cacheKey.split("::").pop()!;
    const relPath  = path.relative(workspaceRoot, filePath);

    const [blameResult, sparkData] = await Promise.all([
      execAsync(`git blame --line-porcelain -- "${relPath}"`, {
        cwd: workspaceRoot, maxBuffer: GIT_MAX_BUFFER,
      }),
      getSparklineForFile(filePath, workspaceRoot),
    ]);

    const lines = parsePorcelain(blameResult.stdout, config, sparkData);
    const entry: BlameCache = { headHash, lines, cachedAt: Date.now() };

    blameCache.set(cacheKey, entry);
    return entry;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Porcelain parser
// ─────────────────────────────────────────────────────────────────────────────

function parsePorcelain(
  raw:       string,
  config:    HeatmapConfig,
  sparkData: FileSparklineData | null
): Map<number, LineBlameInfo> {
  const result = new Map<number, LineBlameInfo>();
  const rawLines = raw.split("\n");
  const nowSec   = Date.now() / 1000;

  let i = 0;
  while (i < rawLines.length) {
    const header = rawLines[i];
    if (!header) { i++; continue; }

    const headerMatch = header.match(/^([0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$/);
    if (!headerMatch) { i++; continue; }

    const commitHash = headerMatch[1];
    const finalLine  = parseInt(headerMatch[2], 10);

    let authorName  = "Unknown";
    let authorEmail = "";
    let authorTime  = 0;
    let summary     = "";

    i++;
    while (i < rawLines.length && !rawLines[i].startsWith("\t")) {
      const kv = rawLines[i];
      if (kv.startsWith("author ") && !kv.startsWith("author-")) {
        authorName = kv.slice(7).trim();
      } else if (kv.startsWith("author-mail ")) {
        authorEmail = kv.slice(12).replace(/[<>]/g, "").trim();
      } else if (kv.startsWith("author-time ")) {
        authorTime = parseInt(kv.slice(12).trim(), 10);
      } else if (kv.startsWith("summary ")) {
        summary = kv.slice(8).trim();
      }
      i++;
    }
    i++; // skip \t<content>

    // Uncommitted hunk
    const isUncommitted = commitHash === "0".repeat(40);
    if (isUncommitted) {
      authorTime = Math.floor(Date.now() / 1000);
      authorName = "You (uncommitted)";
    }

    const ageDays = Math.max(0, Math.floor((nowSec - authorTime) / 86_400));
    const tier    = resolveTier(ageDays, config);
    const sparkBucket = sparkData
      ? resolveSparkBucket(authorTime, sparkData)
      : undefined;

    // Assign deterministic author tint.
    const tintKey = authorEmail || authorName;
    if (!authorTintMap.has(tintKey)) {
      const idx = authorTintMap.size % AUTHOR_TINTS.length;
      authorTintMap.set(tintKey, AUTHOR_TINTS[idx]);
    }

    result.set(finalLine, {
      lineNumber:   finalLine,
      commitHash,
      authorName,
      authorEmail,
      authorTime,
      summary,
      ageDays,
      tier,
      sparkBucket,
      authorTint: authorTintMap.get(tintKey),
    });
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sparkline builder
// ─────────────────────────────────────────────────────────────────────────────

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

function computeSparkline(gitLogOutput: string): FileSparklineData {
  const now     = Date.now();
  const buckets = new Array<number>(8).fill(0);

  for (const line of gitLogOutput.split("\n")) {
    const ts = line.trim();
    if (!ts) { continue; }
    const ms  = new Date(ts).getTime();
    if (isNaN(ms)) { continue; }
    const age = now - ms;
    const idx = Math.floor(age / WEEK_MS);
    if (idx >= 0 && idx < 8) {
      // Reverse so bucket[7] = most recent week
      buckets[7 - idx]++;
    }
  }

  const peak = Math.max(...buckets, 1);
  const totalCommits = buckets.reduce((a, b) => a + b, 0);
  return { weeklyBuckets: buckets, peak, totalCommits, computedAt: Date.now() };
}

function resolveSparkBucket(
  authorTime: number,
  _spark:     FileSparklineData
): number {
  const now    = Date.now();
  const ageMs  = now - authorTime * 1000;
  const idx    = Math.floor(ageMs / WEEK_MS);
  // bucket[7] = current week, so sparkBucket = 7 - idx
  const bucket = 7 - Math.min(idx, 7);
  return Math.max(0, Math.min(7, bucket));
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility exports
// ─────────────────────────────────────────────────────────────────────────────

export function resolveTier(ageDays: number, config: HeatmapConfig): FreshnessTier {
  if (ageDays < config.recentDays) { return FreshnessTier.Recent; }
  if (ageDays < config.staleDays)  { return FreshnessTier.Moderate; }
  return FreshnessTier.Stale;
}

export function formatAge(ageDays: number): string {
  if (ageDays === 0)      { return "today"; }
  if (ageDays === 1)      { return "yesterday"; }
  if (ageDays < 7)        { return `${ageDays} days ago`; }
  if (ageDays < 14)       { return "1 week ago"; }
  if (ageDays < 30)       { return `${Math.floor(ageDays / 7)} weeks ago`; }
  if (ageDays < 60)       { return "1 month ago"; }
  if (ageDays < 365)      { return `${Math.floor(ageDays / 30)} months ago`; }
  if (ageDays < 730)      { return "1 year ago"; }
  return `${Math.floor(ageDays / 365)} years ago`;
}

/** Encodes a 8-bucket sparkline as unicode block characters. */
export function bucketsToSparkChars(buckets: number[], peak: number): string {
  const BLOCKS = " ▁▂▃▄▅▆▇█";
  return buckets.map(v => {
    if (peak === 0) { return " "; }
    const norm  = v / peak;
    const index = Math.round(norm * (BLOCKS.length - 1));
    return BLOCKS[index];
  }).join("");
}
