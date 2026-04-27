/**
 * PasteShield — History View Provider
 * 
 * Provides a TreeDataProvider for displaying scan history in the sidebar.
 * Uses VS Code theme colors and icons for a professional, responsive UI.
 * Enhanced with GitHub-style graph icons and improved visual hierarchy.
 */

import * as vscode from 'vscode';
import { HistoryManager, ScanHistoryEntry } from '../../utils/historyManager';

export class HistoryViewProvider implements vscode.TreeDataProvider<HistoryItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<HistoryItem | undefined | null | void> = new vscode.EventEmitter();
  readonly onDidChangeTreeData: vscode.Event<HistoryItem | undefined | null | void> = this._onDidChangeTreeData.event;

  constructor(private historyManager: HistoryManager) {}

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: HistoryItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: HistoryItem): Promise<HistoryItem[]> {
    if (!element) {
      // Root level - show entries or empty state
      const history = this.historyManager.getHistory();
      
      if (history.length === 0) {
        const emptyItem = new HistoryItem(
          'No scan history yet',
          vscode.TreeItemCollapsibleState.None,
          undefined,
          new vscode.ThemeIcon('shield', new vscode.ThemeColor('descriptionForeground'))
        );
        emptyItem.contextValue = 'emptyHistory';
        emptyItem.description = 'Paste something to see security scans here';
        return [emptyItem];
      }

      return history.map(entry => this.createEntryItem(entry));
    }

    // Entry level - show detections
    if (element.entry) {
      return element.entry.detections.map(det => 
        new HistoryItem(
          `${det.type}${det.category ? ` • ${det.category}` : ''}`,
          vscode.TreeItemCollapsibleState.None,
          {
            command: 'pasteShield.showDetectionDetails',
            title: 'Show Details',
            arguments: [det],
          },
          this.getSeverityThemeIcon(det.severity),
          this.getSeverityColorId(det.severity)
        )
      );
    }

    return [];
  }

  private createEntryItem(entry: ScanHistoryEntry): HistoryItem {
    const date = new Date(entry.timestamp);
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const fileLabel = entry.fileName ? this.truncateFileName(entry.fileName) : 'Unknown file';
    const actionIcon = this.getActionThemeIcon(entry.actionTaken);
    
    const label = `${fileLabel}`;
    
    const item = new HistoryItem(
      label,
      vscode.TreeItemCollapsibleState.Expanded,
      undefined,
      actionIcon
    );
    item.entry = entry;
    item.tooltip = `${fileLabel}\nAction: ${entry.actionTaken.toUpperCase()}\nDetections: ${entry.detections.length}\nTime: ${date.toLocaleString()}`;
    item.description = `${timeStr} • ${this.getHighestSeverity(entry.detections)} • ${entry.detections.length} issue${entry.detections.length !== 1 ? 's' : ''}`;
    item.contextValue = 'historyEntry';
    
    // Set resource URI for theming support
    item.resourceUri = vscode.Uri.parse(`pasteshield://${entry.actionTaken}/${entry.id}`);
    
    return item;
  }

  private getHighestSeverity(detections: Array<{ severity: string }>): string {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    let highest = 'low';
    for (const det of detections) {
      if (severityOrder[det.severity as keyof typeof severityOrder] < severityOrder[highest as keyof typeof severityOrder]) {
        highest = det.severity;
      }
    }
    return highest.toUpperCase();
  }

  private truncateFileName(fileName: string): string {
    const parts = fileName.split('/');
    if (parts.length > 3) {
      return '…/' + parts.slice(-3).join('/');
    }
    return fileName;
  }

  private getSeverityThemeIcon(severity: string): vscode.ThemeIcon {
    switch (severity.toLowerCase()) {
      case 'critical': return new vscode.ThemeIcon('error', new vscode.ThemeColor('editorError.foreground'));
      case 'high': return new vscode.ThemeIcon('stop', new vscode.ThemeColor('editorWarning.foreground'));
      case 'medium': return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorInfo.foreground'));
      case 'low': return new vscode.ThemeIcon('info', new vscode.ThemeColor('descriptionForeground'));
      default: return new vscode.ThemeIcon('circle');
    }
  }

  private getSeverityColorId(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical': return 'pasteShield.criticalForeground';
      case 'high': return 'pasteShield.highForeground';
      case 'medium': return 'pasteShield.mediumForeground';
      case 'low': return 'pasteShield.lowForeground';
      default: return 'foreground';
    }
  }

  private getActionThemeIcon(action: string): vscode.ThemeIcon {
    switch (action) {
      case 'pasted': return new vscode.ThemeIcon('check-circle', new vscode.ThemeColor('terminal.ansiGreen'));
      case 'cancelled': return new vscode.ThemeIcon('skip', new vscode.ThemeColor('terminal.ansiRed'));
      case 'ignored': return new vscode.ThemeIcon('eye-closed', new vscode.ThemeColor('terminal.ansiYellow'));
      default: return new vscode.ThemeIcon('circle');
    }
  }
}

export class HistoryItem extends vscode.TreeItem {
  public entry?: ScanHistoryEntry;

  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly command?: vscode.Command,
    iconPath?: vscode.ThemeIcon,
    colorId?: string,
  ) {
    super(label, collapsibleState);
    
    if (iconPath) {
      this.iconPath = iconPath;
    }
    
    // Apply custom color if provided (for tree item foreground)
    if (colorId) {
      // The color is applied via the icon's ThemeColor or through CSS in package.json
      // VS Code doesn't directly support per-item text colors, but we use theme icons
    }
  }
}
