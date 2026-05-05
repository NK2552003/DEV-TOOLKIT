/**
 * workspaceScanService.ts
 *
 * Performs a background scan of the workspace to compute freshness scores for
 * every tracked source file, then emits a ranked list of the stalest files
 * to the Dashboard.
 *
 * Design:
 *  - Uses `git ls-files` to enumerate tracked files (avoids stat-ing the
 *    entire node_modules tree).
 *  - Processes files in batches of 8, spaced 50 ms apart, to avoid saturating
 *    the git subprocess pool or blocking the UI thread.
 *  - Emits progress via `onProgress` and results via `onComplete`.
 *  - Results are cached for 10 minutes so repeated Dashboard opens are instant.
 */

import { exec }  from "child_process";
import * as path from "path";
import * as util from "util";
import { FileStaleness, HeatmapConfig } from "./types";
import { getBlameForFile }              from "./gitBlameService";
import { computeFreshnessScore }        from "./freshnessScoreService";

const execAsync  = util.promisify(exec);
const BATCH_SIZE = 8;
const BATCH_DELAY_MS = 60;

/** File extensions to scan. */
const SCAN_EXTS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rs", ".rb", ".java", ".cs", ".cpp", ".c",
  ".vue", ".svelte",
]);

let cachedResult: FileStaleness[] | null = null;
let cachedAt = 0;
const CACHE_TTL = 10 * 60 * 1000;

let scanRunning = false;

export interface ScanCallbacks {
  onProgress: (done: number, total: number) => void;
  onComplete: (files: FileStaleness[]) => void;
}

export async function scanWorkspace(
  workspaceRoot: string,
  config:        HeatmapConfig,
  callbacks:     ScanCallbacks
): Promise<void> {
  if (Date.now() - cachedAt < CACHE_TTL && cachedResult) {
    callbacks.onComplete(cachedResult);
    return;
  }

  if (scanRunning) { return; }
  scanRunning = true;

  try {
    const tracked = await listTrackedFiles(workspaceRoot);
    const filtered = tracked.filter(f =>
      SCAN_EXTS.has(path.extname(f).toLowerCase())
    );

    const results: FileStaleness[] = [];
    let done = 0;

    for (let i = 0; i < filtered.length; i += BATCH_SIZE) {
      const batch = filtered.slice(i, i + BATCH_SIZE);

      await Promise.all(batch.map(async relPath => {
        const fsPath = path.join(workspaceRoot, relPath);
        try {
          const cache = await getBlameForFile(fsPath, workspaceRoot, config);
          if (!cache || cache.lines.size === 0) { return; }

          const score = computeFreshnessScore(cache.lines, config);
          results.push({
            fsPath,
            relPath,
            score:      score.score,
            grade:      score.grade,
            avgAgeDays: score.avgAgeDays,
            stalePct:   score.stalePct,
          });
        } catch {
          // skip problematic files silently
        }
      }));

      done += batch.length;
      callbacks.onProgress(done, filtered.length);

      // Yield to event loop between batches.
      await sleep(BATCH_DELAY_MS);
    }

    // Sort by stalePct descending, then avgAgeDays.
    results.sort((a, b) =>
      b.stalePct !== a.stalePct
        ? b.stalePct - a.stalePct
        : b.avgAgeDays - a.avgAgeDays
    );

    const top10     = results.slice(0, 10);
    cachedResult    = top10;
    cachedAt        = Date.now();
    callbacks.onComplete(top10);

  } finally {
    scanRunning = false;
  }
}

export function invalidateScanCache(): void {
  cachedResult = null;
  cachedAt     = 0;
}

async function listTrackedFiles(workspaceRoot: string): Promise<string[]> {
  const { stdout } = await execAsync("git ls-files", {
    cwd: workspaceRoot, maxBuffer: 5 * 1024 * 1024,
  });
  return stdout.trim().split("\n").filter(Boolean);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
