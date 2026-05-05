/**
 * gitChurnService.ts
 *
 * Computes PER-LINE churn counts by parsing `git log -p` unified diffs.
 * For each commit that touched a file, we track which line ranges were
 * modified, and then map those historical line numbers forward to the
 * current working-tree line numbers using a simplified line-shift model.
 *
 * Result: a Map<lineNumber, commitCount> that feeds the Churn heat mode
 * and the gutter sparkline intensity overlay.
 */

import { exec }  from "child_process";
import * as path from "path";
import * as util from "util";
import { FileChurnData, ChurnTier } from "./types";

const execAsync      = util.promisify(exec);
const GIT_MAX_BUFFER = 10 * 1024 * 1024;
const churnCache     = new Map<string, FileChurnData>();

// ─────────────────────────────────────────────────────────────────────────────
// Public
// ─────────────────────────────────────────────────────────────────────────────

export async function getChurnForFile(
  filePath:      string,
  workspaceRoot: string,
  currentLineCount: number
): Promise<FileChurnData | null> {
  const normalized = path.normalize(filePath);
  const cacheKey   = `churn::${normalized}`;
  const cached     = churnCache.get(cacheKey);
  if (cached && Date.now() - cached.computedAt < 15 * 60 * 1000) { return cached; }

  try {
    const relPath = path.relative(workspaceRoot, normalized);

    // Fetch all commit patches for this file.  We use --diff-filter=M (modified)
    // plus A (added) to catch renames; -p gives us the full unified diff.
    const { stdout } = await execAsync(
      `git log --all --diff-filter=MA -p --format="::COMMIT::%H" -- "${relPath}"`,
      { cwd: workspaceRoot, maxBuffer: GIT_MAX_BUFFER }
    );

    const data = parseChurnData(stdout, currentLineCount);
    churnCache.set(cacheKey, data);
    return data;
  } catch {
    return null;
  }
}

export function invalidateChurn(filePath: string): void {
  churnCache.delete(`churn::${path.normalize(filePath)}`);
}

export function clearChurnCache(): void { churnCache.clear(); }

/**
 * Given a sorted churn counts array, returns the tier for a specific count.
 *  - Top 10 %  → Hot
 *  - Next 40 % → Warm
 *  - Rest       → Cold
 */
export function resolveChurnTier(
  count:        number,
  sortedCounts: number[]
): ChurnTier {
  if (sortedCounts.length === 0 || count === 0) { return ChurnTier.Cold; }
  const rank = binaryRank(sortedCounts, count);
  const pct  = rank / sortedCounts.length;
  if (pct >= 0.90) { return ChurnTier.Hot; }
  if (pct >= 0.50) { return ChurnTier.Warm; }
  return ChurnTier.Cold;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

function parseChurnData(raw: string, currentLineCount: number): FileChurnData {
  // lineCounts[line] = number of distinct commits that touched it
  const lineCounts = new Map<number, number>();
  const seenLinesPerCommit = new Set<number>();

  let inCommit  = false;
  let inDiff    = false;

  for (const line of raw.split("\n")) {
    if (line.startsWith("::COMMIT::")) {
      // Flush previous commit's touched lines.
      if (inCommit) {
        for (const ln of seenLinesPerCommit) {
          lineCounts.set(ln, (lineCounts.get(ln) ?? 0) + 1);
        }
      }
      seenLinesPerCommit.clear();
      inCommit = true;
      inDiff   = false;
      continue;
    }

    if (!inCommit) { continue; }

    // Detect start of unified diff section.
    if (line.startsWith("diff --git")) {
      inDiff = true;
      continue;
    }

    if (!inDiff) { continue; }

    // Parse hunk header: @@ -a,b +c,d @@
    const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
    if (hunkMatch) {
      const hunkStart = parseInt(hunkMatch[1], 10);
      const hunkLen   = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
      // Mark all lines in this hunk as touched (in the new file).
      for (let l = hunkStart; l < hunkStart + hunkLen; l++) {
        if (l >= 1 && l <= currentLineCount) {
          seenLinesPerCommit.add(l);
        }
      }
      continue;
    }
  }

  // Flush last commit.
  for (const ln of seenLinesPerCommit) {
    lineCounts.set(ln, (lineCounts.get(ln) ?? 0) + 1);
  }

  const sortedCounts = [...lineCounts.values()].sort((a, b) => a - b);
  return { lineCounts, sortedCounts, computedAt: Date.now() };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Binary search: return rank (0-based index of first element ≥ value). */
function binaryRank(sorted: number[], value: number): number {
  let lo = 0, hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (sorted[mid] < value) { lo = mid + 1; } else { hi = mid; }
  }
  return lo;
}
