/**
 * dashboardPanel.ts
 *
 * A rich WebviewPanel Dashboard that presents:
 *  1. Freshness Score ring (animated SVG, 0–100 + letter grade)
 *  2. Tier distribution donut chart (Chart.js)
 *  3. 8-week sparkline bar chart (Chart.js)
 *  4. Author contribution table with tint badges and per-author freshness
 *  5. Stale-files ranking — top-10 stalest files in the workspace
 *  6. Live "Refresh" and mode-switch controls that post messages back
 *
 * The panel re-renders whenever the controller calls `updateScore()` or
 * `updateStalestFiles()`.  All communication is via panel.webview.postMessage
 * / onDidReceiveMessage — no shared state outside the message bus.
 */

import * as vscode from "vscode";
import {
  FreshnessScore,
  FileSparklineData,
  FileStaleness,
  HeatMode,
} from "./types";
import { buildDashboardHtml } from "./dashboardHtml";

export class DashboardPanel implements vscode.Disposable {
  private static _instance: DashboardPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];

  private _score:     FreshnessScore   | null = null;
  private _sparkData: FileSparklineData | null = null;
  private _staleList: FileStaleness[]          = [];
  private _currentFile = "";
  private _currentMode: HeatMode = HeatMode.Age;

  /** Callback fired when user clicks a mode switch or refresh in the panel. */
  onModeChange?: (mode: HeatMode) => void;
  onRefresh?:    () => void;
  onFileOpen?:   (fsPath: string) => void;

  // ─────────────────────────────────────────────────────────────────────────
  // Singleton factory
  // ─────────────────────────────────────────────────────────────────────────

  static createOrShow(extensionUri: vscode.Uri): DashboardPanel {
    const column = vscode.ViewColumn.Beside;

    if (DashboardPanel._instance) {
      DashboardPanel._instance._panel.reveal(column);
      return DashboardPanel._instance;
    }

    const panel = vscode.window.createWebviewPanel(
      "freshnessHeatmapDashboard",
      "$(flame) Freshness Dashboard",
      column,
      {
        enableScripts:              true,
        retainContextWhenHidden:    true,
        localResourceRoots:         [extensionUri],
      }
    );

    DashboardPanel._instance = new DashboardPanel(panel, extensionUri);
    return DashboardPanel._instance;
  }

  static getInstance(): DashboardPanel | undefined {
    return DashboardPanel._instance;
  }

  private constructor(
    panel:          vscode.WebviewPanel,
    extensionUri:   vscode.Uri
  ) {
    this._panel = panel;
    this._extensionUri = extensionUri;
    this._render();

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(msg => {
      switch (msg.type) {
        case "setMode":
          this._currentMode = msg.mode as HeatMode;
          this.onModeChange?.(this._currentMode);
          break;
        case "refresh":
          this.onRefresh?.();
          break;
        case "openFile":
          this.onFileOpen?.(msg.path);
          break;
      }
    }, null, this._disposables);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public update API
  // ─────────────────────────────────────────────────────────────────────────

  updateScore(
    filePath:  string,
    score:     FreshnessScore,
    sparkData: FileSparklineData | null
  ): void {
    this._currentFile = filePath;
    this._score       = score;
    this._sparkData   = sparkData;
    this._postUpdate();
  }

  updateStalestFiles(files: FileStaleness[]): void {
    this._staleList = files;
    this._postUpdate();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Message to webview
  // ─────────────────────────────────────────────────────────────────────────

  private _postUpdate(): void {
    this._panel.webview.postMessage({
      type:        "update",
      score:       this._score,
      sparkData:   this._sparkData,
      staleList:   this._staleList,
      currentFile: this._currentFile,
      currentMode: this._currentMode,
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // HTML render
  // ─────────────────────────────────────────────────────────────────────────

  private _render(): void {
    this._panel.webview.html = buildDashboardHtml(
      this._panel.webview,
      this._extensionUri
    );
  }

  dispose(): void {
    DashboardPanel._instance = undefined;
    this._panel.dispose();
    for (const d of this._disposables) { d.dispose(); }
  }
}
