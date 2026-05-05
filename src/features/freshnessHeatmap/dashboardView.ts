import * as vscode from "vscode";

import {
  FreshnessScore,
  FileSparklineData,
  FileStaleness,
  HeatMode,
} from "./types";
import { buildDashboardHtml } from "./dashboardHtml";

export class FreshnessDashboardViewProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;

  private _score:     FreshnessScore   | null = null;
  private _sparkData: FileSparklineData | null = null;
  private _staleList: FileStaleness[]          = [];
  private _currentFile = "";
  private _currentMode: HeatMode = HeatMode.Age;

  /** Callback fired when user clicks a mode switch or refresh in the panel. */
  onModeChange?: (mode: HeatMode) => void;
  onRefresh?:    () => void;
  onFileOpen?:   (fsPath: string) => void;

  constructor(private readonly context: vscode.ExtensionContext) {}

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    this.view.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.context.extensionUri],
    };
    this.view.webview.html = buildDashboardHtml(
      this.view.webview,
      this.context.extensionUri
    );

    const messageDisposable = this.view.webview.onDidReceiveMessage(msg => {
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
    });

    this.view.onDidDispose(() => {
      messageDisposable.dispose();
      this.view = undefined;
    });

    this.postUpdate();
  }

  reveal(): void {
    vscode.commands.executeCommand("workbench.view.extension.devToolkit");
    vscode.commands.executeCommand("devToolkit.freshnessDashboard.focus");
  }

  isReady(): boolean {
    return !!this.view;
  }

  updateScore(
    filePath:  string,
    score:     FreshnessScore,
    sparkData: FileSparklineData | null
  ): void {
    this._currentFile = filePath;
    this._score       = score;
    this._sparkData   = sparkData;
    this.postUpdate();
  }

  updateStalestFiles(files: FileStaleness[]): void {
    this._staleList = files;
    this.postUpdate();
  }

  setMode(mode: HeatMode): void {
    this._currentMode = mode;
    this.postUpdate();
  }

  private postUpdate(): void {
    if (!this.view) { return; }
    this.view.webview.postMessage({
      type:        "update",
      score:       this._score,
      sparkData:   this._sparkData,
      staleList:   this._staleList,
      currentFile: this._currentFile,
      currentMode: this._currentMode,
    });
  }
}
