/**
 * PasteShield — History Manager
 * 
 * Provides persistent storage for scan history across sessions.
 * Uses VS Code's globalState for opt-in persistent storage.
 */

import * as vscode from 'vscode';

const HISTORY_STORAGE_KEY = 'pasteShield.scanHistory';
const MAX_HISTORY_ENTRIES = 100;

export interface ScanHistoryEntry {
  id: string;
  timestamp: number;
  fileName?: string;
  detections: Array<{
    type: string;
    severity: string;
    category?: string;
  }>;
  actionTaken: 'pasted' | 'pasted_silent' | 'cancelled' | 'ignored';
}

export class HistoryManager {
  private static instance: HistoryManager | undefined;
  private context: vscode.ExtensionContext;

  private constructor(context: vscode.ExtensionContext) {
    this.context = context;
  }

  public static getInstance(context: vscode.ExtensionContext): HistoryManager {
    if (!HistoryManager.instance) {
      HistoryManager.instance = new HistoryManager(context);
    }
    return HistoryManager.instance;
  }

  /**
   * Check if history tracking is enabled in settings
   */
  public isEnabled(): boolean {
    const config = vscode.workspace.getConfiguration('pasteShield');
    // History is now always enabled by default for better UX
    return config.get<boolean>('enableHistory', true);
  }

  /**
   * Add a new scan entry to history
   */
  public async addEntry(entry: Omit<ScanHistoryEntry, 'id' | 'timestamp'>): Promise<void> {
    if (!this.isEnabled()) {
      return;
    }

    const history = this.getHistory();
    
    const newEntry: ScanHistoryEntry = {
      ...entry,
      id: this.generateId(),
      timestamp: Date.now(),
    };

    // Add to beginning (most recent first)
    history.unshift(newEntry);

    // Trim to max entries
    if (history.length > MAX_HISTORY_ENTRIES) {
      history.splice(MAX_HISTORY_ENTRIES);
    }

    await this.saveHistory(history);
  }

  /**
   * Get all history entries
   */
  public getHistory(): ScanHistoryEntry[] {
    const stored = this.context.globalState.get<ScanHistoryEntry[]>(HISTORY_STORAGE_KEY, []);
    return stored;
  }

  /**
   * Clear all history
   */
  public async clearHistory(): Promise<void> {
    await this.context.globalState.update(HISTORY_STORAGE_KEY, []);
  }

  /**
   * Get statistics from history
   */
  public getStatistics(): {
    totalScans: number;
    totalDetections: number;
    pastedCount: number;
    cancelledCount: number;
    ignoredCount: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    byType: Record<string, number>;
  } {
    const history = this.getHistory();
    
    const stats = {
      totalScans: history.length,
      totalDetections: 0,
      pastedCount: 0,
      cancelledCount: 0,
      ignoredCount: 0,
      bySeverity: {} as Record<string, number>,
      byCategory: {} as Record<string, number>,
      byType: {} as Record<string, number>,
    };

    for (const entry of history) {
      stats.totalDetections += entry.detections.length;
      
      switch (entry.actionTaken) {
        case 'pasted':
        case 'pasted_silent':
          stats.pastedCount++;
          break;
        case 'cancelled':
          stats.cancelledCount++;
          break;
        case 'ignored':
          stats.ignoredCount++;
          break;
      }

      for (const detection of entry.detections) {
        stats.bySeverity[detection.severity] = (stats.bySeverity[detection.severity] || 0) + 1;
        if (detection.category) {
          stats.byCategory[detection.category] = (stats.byCategory[detection.category] || 0) + 1;
        }
        stats.byType[detection.type] = (stats.byType[detection.type] || 0) + 1;
      }
    }

    return stats;
  }

  /**
   * Export history as JSON
   */
  public exportAsJson(): string {
    const history = this.getHistory();
    return JSON.stringify(history, null, 2);
  }

  /**
   * Export history as plain text
   */
  public exportAsText(): string {
    const history = this.getHistory();
    const lines: string[] = [
      'PasteShield Scan History Report',
      '='.repeat(50),
      `Generated: ${new Date().toLocaleString()}`,
      `Total Entries: ${history.length}`,
      '',
    ];

    for (const entry of history) {
      const date = new Date(entry.timestamp).toLocaleString();
      const file = entry.fileName || 'Unknown file';
      const action = entry.actionTaken.toUpperCase();
      const detectionCount = entry.detections.length;
      
      lines.push(`[${date}] ${file}`);
      lines.push(`  Action: ${action}`);
      lines.push(`  Detections: ${detectionCount}`);
      
      for (const det of entry.detections) {
        lines.push(`    - [${det.severity.toUpperCase()}] ${det.type}${det.category ? ` (${det.category})` : ''}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Save history to storage
   */
  private async saveHistory(history: ScanHistoryEntry[]): Promise<void> {
    await this.context.globalState.update(HISTORY_STORAGE_KEY, history);
  }

  /**
   * Generate unique ID for entry
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }
}
