/**
 * freshnessHeatmapController.ts
 *
 * Central orchestrator for the enhanced Freshness Heatmap system.
 *
 * Coordinates:
 *  - gitBlameService        (blame + sparklines)
 *  - gitChurnService        (per-line modification counts)
 *  - heatmapDecorator       (Age / Churn / Author visual modes)
 *  - freshnessScoreService  (composite 0–100 score + grade)
 *  - zombieDiagnosticsService (Problems-panel Diagnostics)
 *  - inlayHintsProvider     (end-of-line age/churn hints)
 *  - dashboardPanel         (Webview Dashboard)
 *  - workspaceScanService   (background stale-file ranking)
 */

import * as vscode from "vscode";
import * as path   from "path";

import { getBlameForFile, getSparklineForFile, invalidateFile, clearCache }
  from "./gitBlameService";
import { getChurnForFile, invalidateChurn, clearChurnCache, resolveChurnTier }
  from "./gitChurnService";
import { buildDecorationTypes, disposeDecorationTypes, applyDecorations, clearDecorations, disposeAuthorTypes }
  from "./heatmapDecorator";
import { computeFreshnessScore }
  from "./freshnessScoreService";
import { updateDiagnostics, clearAllDiagnostics, disposeDiagnostics }
  from "./zombieDiagnosticsService";
import { FreshnessInlayHintsProvider }
  from "./inlayHintsProvider";
import { FreshnessDashboardViewProvider }
  from "./dashboardView";
import { scanWorkspace, invalidateScanCache }
  from "./workspaceScanService";
import { HeatmapConfig, HeatMode }
  from "./types";

// ─────────────────────────────────────────────────────────────────────────────
// Config loader
// ─────────────────────────────────────────────────────────────────────────────

function loadConfig(): HeatmapConfig {
  const cfg = vscode.workspace.getConfiguration("devToolkit.freshnessHeatmap");
  return {
    enabled:             cfg.get<boolean>("enabled",            false),
    mode:                cfg.get<HeatMode>("mode",              HeatMode.Age),
    recentDays:          cfg.get<number>("recentDays",          7),
    staleDays:           cfg.get<number>("staleDays",           30),
    recentColor:         cfg.get<string>("recentColor",         "#4caf50"),
    moderateColor:       cfg.get<string>("moderateColor",       "#ff9800"),
    staleColor:          cfg.get<string>("staleColor",          "#f44336"),
    opacity:             cfg.get<number>("opacity",             0.12),
    maxLines:            cfg.get<number>("maxLines",            10_000),
    showStatusBar:       cfg.get<boolean>("showStatusBar",      true),
    showSparklines:      cfg.get<boolean>("showSparklines",     true),
    showInlayHints:      cfg.get<boolean>("showInlayHints",     true),
    showExplorerBadges:  cfg.get<boolean>("showExplorerBadges", true),
    showDiagnostics:     cfg.get<boolean>("showDiagnostics",    true),
    zombieDays:          cfg.get<number>("zombieDays",          180),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Controller
// ─────────────────────────────────────────────────────────────────────────────

export class FreshnessHeatmapController implements vscode.Disposable {
  private config:         HeatmapConfig;
  private decorTypes:     ReturnType<typeof buildDecorationTypes> | null = null;
  private statusBar:      vscode.StatusBarItem;
  private inlayProvider:  FreshnessInlayHintsProvider;
  private dashboardView?: FreshnessDashboardViewProvider;
  private disposables:    vscode.Disposable[] = [];
  private debounceTimers  = new Map<string, ReturnType<typeof setTimeout>>();
  private decoratedUris   = new Set<string>();
  private context:        vscode.ExtensionContext;

  private loadPersistedState(): void {
    const persisted = this.context.workspaceState.get<string[]>(
      'freshnessHeatmap.decoratedUris'
    ) ?? [];
    this.decoratedUris = new Set(persisted);
  }

  private savePersistedState(): void {
    const uris = Array.from(this.decoratedUris);
    this.context.workspaceState.update(
      'freshnessHeatmap.decoratedUris', 
      uris
    );
  }

  constructor(
    context: vscode.ExtensionContext,
    dashboardView?: FreshnessDashboardViewProvider
  ) {
    this.context = context;
    this.loadPersistedState();
    
    this.config = loadConfig();
    this.dashboardView = dashboardView;

    // Status bar
    this.statusBar = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right, 90
    );
    this.statusBar.command = "devToolkit.toggleFreshnessHeatmap";
    this.statusBar.tooltip = "Click to toggle Freshness Heatmap";
    this.disposables.push(this.statusBar);

    // Inlay hints provider
    this.inlayProvider = new FreshnessInlayHintsProvider(this.config);
    this.disposables.push(
      vscode.languages.registerInlayHintsProvider(
        { scheme: "file" },
        this.inlayProvider
      )
    );
    this.disposables.push(this.inlayProvider);

    if (this.dashboardView) {
      this.dashboardView.onModeChange = async (mode) => {
        await vscode.workspace
          .getConfiguration("devToolkit.freshnessHeatmap")
          .update("mode", mode, vscode.ConfigurationTarget.Global);
      };
      this.dashboardView.onRefresh = () => this.refresh();
      this.dashboardView.onFileOpen = async (fsPath) => {
        const doc = await vscode.workspace.openTextDocument(fsPath);
        await vscode.window.showTextDocument(doc);
      };
    }

    if (this.config.enabled) {
      this.activate();
    }

    this.updateStatusBar();
    this.registerEvents();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public commands
  // ─────────────────────────────────────────────────────────────────────────

  async toggle(): Promise<void> {
    await vscode.workspace
      .getConfiguration("devToolkit.freshnessHeatmap")
      .update("enabled", !this.config.enabled, vscode.ConfigurationTarget.Global);
  }

  async cycleMode(): Promise<void> {
    const modes = [HeatMode.Age, HeatMode.Churn, HeatMode.Author];
    const next  = modes[(modes.indexOf(this.config.mode) + 1) % modes.length];
    await vscode.workspace
      .getConfiguration("devToolkit.freshnessHeatmap")
      .update("mode", next, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage(
      `$(flame) Freshness Heatmap mode: ${modeLabel(next)}`
    );
  }

  async refresh(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { return; }
    const filePath = editor.document.uri.fsPath;
    invalidateFile(filePath);
    invalidateChurn(filePath);
    invalidateScanCache();
    await this.decorateEditor(editor, true);
    vscode.window.showInformationMessage("$(sync) Freshness Heatmap refreshed.");
  }

  openDashboard(): void {
    if (!this.dashboardView) { return; }
    this.dashboardView.reveal();

    // Push current data to dashboard immediately.
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      this.decorateEditor(editor, false).catch(() => {});
    }

    // Kick off background workspace scan.
    const root = this.resolveWorkspaceRoot(
      editor?.document.uri.fsPath ?? (vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "")
    );
    if (root) {
      this.runWorkspaceScan(root);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  dispose(): void {
    this.deactivate();
    disposeDiagnostics();
    disposeAuthorTypes();
    for (const d of this.disposables) { d.dispose(); }
    for (const t of this.debounceTimers.values()) { clearTimeout(t); }
    clearCache();
    clearChurnCache();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event registration
  // ─────────────────────────────────────────────────────────────────────────

  private registerEvents(): void {
    this.disposables.push(
      vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && this.config.enabled) { this.scheduleDecorate(editor); }
      }),

      vscode.workspace.onDidSaveTextDocument(doc => {
        if (!this.config.enabled) { return; }
        invalidateFile(doc.uri.fsPath);
        invalidateChurn(doc.uri.fsPath);
        invalidateScanCache();
        const editor = vscode.window.visibleTextEditors.find(
          e => e.document.uri.toString() === doc.uri.toString()
        );
        if (editor) { this.scheduleDecorate(editor, 0); }
      }),

      vscode.workspace.onDidChangeTextDocument(e => {
        if (!this.config.enabled) { return; }
        invalidateFile(e.document.uri.fsPath);
        const editor = vscode.window.visibleTextEditors.find(
          ed => ed.document.uri.toString() === e.document.uri.toString()
        );
        if (editor) { this.scheduleDecorate(editor, 2_000); }
      }),

      vscode.window.onDidChangeVisibleTextEditors(editors => {
        if (!this.config.enabled) { return; }
        for (const e of editors) { this.scheduleDecorate(e); }
      }),

      vscode.workspace.onDidChangeConfiguration(e => {
        if (e.affectsConfiguration("devToolkit.freshnessHeatmap")) {
          this.onConfigChanged();
        }
      })
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Config change
  // ─────────────────────────────────────────────────────────────────────────

  private onConfigChanged(): void {
    const wasEnabled = this.config.enabled;
    this.config = loadConfig();
    this.inlayProvider.updateConfig(this.config);

    if (this.config.enabled) {
      this.activate();
    } else if (wasEnabled) {
      this.deactivate();
    }

    this.updateStatusBar();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Activate / deactivate
  // ─────────────────────────────────────────────────────────────────────────

  private activate(): void {
    this.decorTypes = buildDecorationTypes(this.config);
    for (const e of vscode.window.visibleTextEditors) {
      this.scheduleDecorate(e, 0);
    }
  }

  private deactivate(): void {
    if (this.decorTypes) {
      for (const e of vscode.window.visibleTextEditors) {
        clearDecorations(e, this.decorTypes);
      }
    }
    disposeDecorationTypes();
    this.decorTypes = null;
    clearAllDiagnostics();
    this.savePersistedState();
    this.decoratedUris.clear();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Decoration pipeline
  // ─────────────────────────────────────────────────────────────────────────

  private scheduleDecorate(
    editor:  vscode.TextEditor,
    delayMs: number = 300
  ): void {
    const key = editor.document.uri.toString();
    const existing = this.debounceTimers.get(key);
    if (existing !== undefined) { clearTimeout(existing); }

    const handle = setTimeout(() => {
      this.debounceTimers.delete(key);
      this.decorateEditor(editor, false).catch(() => {});
    }, delayMs);

    this.debounceTimers.set(key, handle);
  }

  private async decorateEditor(
    editor: vscode.TextEditor,
    force:  boolean
  ): Promise<void> {
    if (!this.config.enabled || !this.decorTypes) { return; }

    const doc = editor.document;
    if (doc.uri.scheme !== "file") { return; }
    if (!force && doc.lineCount > this.config.maxLines) {
      clearDecorations(editor, this.decorTypes);
      return;
    }

    const workspaceRoot = this.resolveWorkspaceRoot(doc.uri.fsPath);
    if (!workspaceRoot) {
      applyDecorations(editor, null, this.decorTypes, this.config, null);
      return;
    }

    // Fetch blame + sparkline + churn in parallel.
    const [cache, sparkData, churnData] = await Promise.all([
      getBlameForFile(doc.uri.fsPath, workspaceRoot, this.config),
      getSparklineForFile(doc.uri.fsPath, workspaceRoot),
      getChurnForFile(doc.uri.fsPath, workspaceRoot, doc.lineCount),
    ]);

    // Guard: editor may no longer be visible.
    if (!vscode.window.visibleTextEditors.includes(editor)) { return; }

    // Merge churn data into blame lines.
    if (cache && churnData) {
      for (const [ln, info] of cache.lines) {
        const count = churnData.lineCounts.get(ln) ?? 0;
        info.churnCount = count;
        info.churnTier  = resolveChurnTier(count, churnData.sortedCounts);
      }
    }

    applyDecorations(
      editor,
      cache ? cache.lines : null,
      this.decorTypes,
      this.config,
      sparkData
    );

    this.savePersistedState();

    // Update inlay hints.
    if (cache) {
      this.inlayProvider.updateBlame(doc.uri, cache.lines);
    }

    // Update diagnostics.
    if (cache) {
      updateDiagnostics(doc, cache.lines, this.config);
    }

    // Compute freshness score + push to Dashboard (if open).
    if (cache) {
      const score = computeFreshnessScore(cache.lines, this.config);
      this.updateStatusBarScore(score.score, score.grade);
      this.dashboardView?.updateScore(
        path.basename(doc.uri.fsPath),
        score,
        sparkData
      );
    }

    this.decoratedUris.add(doc.uri.toString());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Workspace scan
  // ─────────────────────────────────────────────────────────────────────────

  private async runWorkspaceScan(workspaceRoot: string): Promise<void> {
    if (!this.dashboardView) { return; }

    await scanWorkspace(workspaceRoot, this.config, {
      onProgress: (done, total) => {
        this.statusBar.text = `$(loading~spin) Scanning ${done}/${total}…`;
      },
      onComplete: files => {
        this.dashboardView?.updateStalestFiles(files);
        this.updateStatusBar();
      },
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status bar
  // ─────────────────────────────────────────────────────────────────────────

  private updateStatusBar(): void {
    if (!this.config.showStatusBar) { this.statusBar.hide(); return; }

    if (!this.config.enabled) {
      this.statusBar.text = "$(flame) Heatmap";
      this.statusBar.tooltip = "Freshness Heatmap — OFF (click to enable)";
      this.statusBar.show();
      return;
    }

    const modeIcon = {
      [HeatMode.Age]:    "$(clock)",
      [HeatMode.Churn]:  "$(flame)",
      [HeatMode.Author]: "$(person)",
    }[this.config.mode] ?? "$(flame)";

    this.statusBar.text = `${modeIcon} Heatmap`;
    this.statusBar.tooltip = `Freshness Heatmap — ${modeLabel(this.config.mode)} mode (click to toggle)`;
    this.statusBar.show();
  }

  private updateStatusBarScore(score: number, grade: string): void {
    if (!this.config.showStatusBar || !this.config.enabled) { return; }
    const modeIcon = {
      [HeatMode.Age]:    "$(clock)",
      [HeatMode.Churn]:  "$(flame)",
      [HeatMode.Author]: "$(person)",
    }[this.config.mode] ?? "$(flame)";

    this.statusBar.text = `${modeIcon} ${score} (${grade})`;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private resolveWorkspaceRoot(filePath: string): string | null {
    const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(filePath));
    return folder ? folder.uri.fsPath : null;
  }
}

function modeLabel(mode: HeatMode): string {
  return { [HeatMode.Age]: "Age", [HeatMode.Churn]: "Churn", [HeatMode.Author]: "Author" }[mode] ?? mode;
}
