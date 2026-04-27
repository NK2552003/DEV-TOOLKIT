/**
 * PasteShield
 *
 * Intercepts clipboard paste operations in the editor, scans the content
 * for secrets / risky patterns, and surfaces a non-blocking warning with
 * actionable choices before the text is committed to the document.
 *
 * Architecture:
 *  • Overrides the default `editor.action.clipboardPasteAction` keybinding
 *    via a dedicated `pasteShield.paste` command (registered in package.json).
 *  • If no issues are found → delegates to the original paste immediately.
 *  • If issues are found → shows a warning with "Paste Anyway / Cancel / Details".
 *  • Inline decorations mark the insertion point for warned pastes (optional).
 *  • CodeLens providers display warnings above detected secrets in open files.
 *
 * Exceptions:
 *  • .env and .env.local files are excluded from paste interception entirely.
 *    (These files are intentionally used to store secrets locally.)
 *  • CodeLens scanning still runs on all file types including .env files.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { scanContent, DetectionResult, Severity } from './patternDetector';
import { getConfig, meetsSeverityThreshold, CONFIG_SECTION } from './pasteShieldConfig';
import { createLogger } from '../../utils/logger';
import { debounce } from '../../utils/debounce';

import { HistoryViewProvider, HistoryItem } from './historyViewProvider';
import { StatisticsManager } from './statisticsManager';
import { IgnorePatternsManager } from './ignorePatternsManager';
import { HistoryManager } from '../../utils/historyManager';

const logger = createLogger('PasteShield');

// ─── Constants ───────────────────────────────────────────────────────────────

const COMMAND_ID = 'pasteShield.paste';
const TOGGLE_COMMAND_ID = 'pasteShield.toggle';
const SHOW_REPORT_COMMAND_ID = 'pasteShield.showLastReport';
const CODELENS_FIX_COMMAND_ID = 'pasteShield.codeLensFix';
const CODELENS_IGNORE_COMMAND_ID = 'pasteShield.codeLensIgnore';
const CODELENS_DETAILS_COMMAND_ID = 'pasteShield.codeLensDetails';
const SHOW_DETECTION_DETAILS_COMMAND_ID = 'pasteShield.showDetectionDetails';
const SHOW_HISTORY_COMMAND_ID = 'pasteShield.showHistory';
const CLEAR_HISTORY_COMMAND_ID = 'pasteShield.clearHistory';
const EXPORT_HISTORY_JSON_COMMAND_ID = 'pasteShield.exportHistoryJson';
const EXPORT_HISTORY_TEXT_COMMAND_ID = 'pasteShield.exportHistoryText';
const REFRESH_HISTORY_COMMAND_ID = 'pasteShield.refreshHistory';
const SHOW_STATISTICS_COMMAND_ID = 'pasteShield.showStatistics';
const EXPORT_AUDIT_LOG_COMMAND_ID = 'pasteShield.exportAuditLog';
const SHOW_ROTATION_REMINDERS_COMMAND_ID = 'pasteShield.showRotationReminders';
const ADD_TO_WORKSPACE_IGNORE_COMMAND_ID = 'pasteShield.addToWorkspaceIgnore';

/**
 * File names (basename only, case-insensitive) that are excluded from
 * paste interception. Secrets in these files are intentional and managed
 * locally — PasteShield should not block pasting into them.
 *
 * NOTE: CodeLens still scans these files so existing secrets are surfaced.
 */
const PASTE_EXCLUDED_FILENAMES = new Set(['.env', '.env.local']);

// Use VS Code theme colors instead of hardcoded colors for better responsiveness
const SEVERITY_THEME_COLORS: Record<Severity, vscode.ThemeColor> = {
  critical: new vscode.ThemeColor('editorError.foreground'),
  high:     new vscode.ThemeColor('editorWarning.foreground'),
  medium:   new vscode.ThemeColor('editorInfo.foreground'),
  low:      new vscode.ThemeColor('descriptionForeground'),
};

// ─── Utilities ────────────────────────────────────────────────────────────────

/**
 * Returns true if the document's filename is in the paste-exclusion list.
 * Comparison is case-insensitive so `.ENV` also matches on Windows.
 */
function isPasteExcludedFile(document: vscode.TextDocument): boolean {
  const basename = path.basename(document.fileName).toLowerCase();
  for (const excluded of PASTE_EXCLUDED_FILENAMES) {
    if (basename === excluded.toLowerCase()) {
      return true;
    }
  }
  return false;
}

// ─── Decoration Types ─────────────────────────────────────────────────────────

function createDecorationTypes(): {
  critical: vscode.TextEditorDecorationType;
  high: vscode.TextEditorDecorationType;
  medium: vscode.TextEditorDecorationType;
  low: vscode.TextEditorDecorationType;
} {
  const make = (themeColor: vscode.ThemeColor, glyph: string) =>
    vscode.window.createTextEditorDecorationType({
      after: {
        contentText: ` ${glyph} PasteShield`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
        fontStyle: 'italic',
        margin: '0 0 0 8px',
      },
      overviewRulerColor: themeColor,
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      light: { borderColor: themeColor, borderStyle: 'dashed', borderWidth: '1px' },
      dark:  { borderColor: themeColor, borderStyle: 'dashed', borderWidth: '1px' },
    });

  return {
    critical: make(SEVERITY_THEME_COLORS.critical, '$(error)'),
    high:     make(SEVERITY_THEME_COLORS.high,     '$(shield)'),
    medium:   make(SEVERITY_THEME_COLORS.medium,   '$(warning)'),
    low:      make(SEVERITY_THEME_COLORS.low,      '$(info)'),
  };
}

// ─── CodeLens Provider ────────────────────────────────────────────────────────

/**
 * One CodeLens "block" per detected issue — renders above the matched line
 * with three lenses side-by-side: severity badge | fix action | ignore action.
 */
class PasteShieldCodeLensProvider implements vscode.CodeLensProvider {
  private readonly _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  /** Called by refresh() when a document is re-scanned. */
  refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken,
  ): vscode.CodeLens[] {
    const config = getConfig();
    if (!config.enabled) {
      return [];
    }

    const text = document.getText();
    const detections = scanContent(text, {
      ignoredPatterns: config.ignoredPatterns,
    });

    const filtered = detections.filter(d =>
      meetsSeverityThreshold(d.severity, config.minimumSeverity),
    );

    const lenses: vscode.CodeLens[] = [];

    for (const det of filtered) {
      // det.line is 1-indexed; vscode lines are 0-indexed
      const lineIndex = (det.line ?? 1) - 1;
      const lineCount = document.lineCount;
      const safeLine = Math.min(Math.max(lineIndex, 0), lineCount - 1);
      const lineLength = document.lineAt(safeLine).text.length;
      const range = new vscode.Range(safeLine, 0, safeLine, lineLength);

      const severityIcon = severityToIcon(det.severity);
      const severityLabel = det.severity.toUpperCase();

      // Lens 1 — severity + type badge (non-interactive label)
      lenses.push(
        new vscode.CodeLens(range, {
          title: `${severityIcon} PasteShield [${severityLabel}]: ${det.type}`,
          command: CODELENS_DETAILS_COMMAND_ID,
          arguments: [[det]],
          tooltip: det.description,
        }),
      );

      // Lens 2 — "View details" action
      lenses.push(
        new vscode.CodeLens(range, {
          title: '$(info) View Details',
          command: CODELENS_DETAILS_COMMAND_ID,
          arguments: [[det]],
          tooltip: 'Open the full security report for this detection',
        }),
      );

      // Lens 3 — "Ignore this pattern" action
      lenses.push(
        new vscode.CodeLens(range, {
          title: '$(mute) Ignore Pattern',
          command: CODELENS_IGNORE_COMMAND_ID,
          arguments: [det.type],
          tooltip: `Add "${det.type}" to pasteShield.ignoredPatterns`,
        }),
      );
    }

    return lenses;
  }
}

function severityToIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return '$(error)';
    case 'high':     return '$(shield)';
    case 'medium':   return '$(warning)';
    case 'low':      return '$(info)';
  }
}

// ─── State ────────────────────────────────────────────────────────────────────

let decorationTypes: ReturnType<typeof createDecorationTypes> | undefined;
let lastReport: DetectionResult[] = [];
let statusBarItem: vscode.StatusBarItem | undefined;
let activeDecorations: Array<{
  editor: vscode.TextEditor;
  type: vscode.TextEditorDecorationType;
}> = [];
let codeLensProvider: PasteShieldCodeLensProvider | undefined;
let historyManager: HistoryManager | undefined;
let historyViewProvider: HistoryViewProvider | undefined;
let historyTreeView: vscode.TreeView<HistoryItem> | undefined;
let statisticsManager: StatisticsManager | undefined;
let ignorePatternsManager: IgnorePatternsManager | undefined;

/**
 * Debounced so rapid editor-tab switching (e.g. Ctrl+Tab held down) doesn't
 * thrash the visible-editors Set rebuild on every intermediate event.
 */
const debouncedPruneDecorations = debounce(pruneStaleDecorations, 150);

/**
 * Debounced CodeLens refresh — avoids hammering the provider on every keystroke.
 */
const debouncedRefreshCodeLens = debounce(() => {
  codeLensProvider?.refresh();
}, 500);

// ─── Activation ───────────────────────────────────────────────────────────────

export function registerPasteShield(context: vscode.ExtensionContext): void {
  decorationTypes  = createDecorationTypes();
  codeLensProvider = new PasteShieldCodeLensProvider();

  // Initialize History Manager
  historyManager = HistoryManager.getInstance(context);
  historyViewProvider = new HistoryViewProvider(historyManager);

  // Initialize Statistics Manager
  statisticsManager = StatisticsManager.getInstance(historyManager);

  // Initialize Ignore Patterns Manager
  ignorePatternsManager = IgnorePatternsManager.getInstance(context);

  // Register History Tree View in sidebar
  historyTreeView = vscode.window.createTreeView('pasteShieldHistory', {
    treeDataProvider: historyViewProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(historyTreeView);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    90,
  );
  updateStatusBar(true);

  // ── CodeLens registration ──────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { scheme: 'file' }, // all files
      codeLensProvider,
    ),
  );

  // CodeLens commands
  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_DETAILS_COMMAND_ID,
      async (detections: DetectionResult[]) => {
        lastReport = detections;
        await showDetailsPanel(detections);
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_IGNORE_COMMAND_ID,
      async (patternName: string) => {
        await addToIgnoredPatterns(patternName);
        codeLensProvider?.refresh();
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_FIX_COMMAND_ID,
      async (_patternName: string) => {
        // Placeholder: open settings or guide user to rotate the credential
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'pasteShield.ignoredPatterns',
        );
      },
    ),
  );

  // Show detection details from history view
  context.subscriptions.push(
    vscode.commands.registerCommand(
      SHOW_DETECTION_DETAILS_COMMAND_ID,
      async (detection: { type: string; severity: string; category?: string }) => {
        await vscode.window.showInformationMessage(
          `Detection Details\nType: ${detection.type}\nSeverity: ${detection.severity.toUpperCase()}${detection.category ? `\nCategory: ${detection.category}` : ''}`,
          { modal: true }
        );
      },
    ),
  );

  // ── Paste intercept command ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(COMMAND_ID, handlePaste),
  );

  // Toggle on/off from status bar or command palette
  context.subscriptions.push(
    vscode.commands.registerCommand(TOGGLE_COMMAND_ID, togglePasteShield),
  );

  // Show last scan report
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_REPORT_COMMAND_ID, showLastReport),
  );

  // ── History commands ───────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_HISTORY_COMMAND_ID, () => {
      if (historyTreeView) {
        historyTreeView.reveal(undefined as unknown as HistoryItem, { focus: true, select: true });
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(CLEAR_HISTORY_COMMAND_ID, async () => {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear all scan history?',
        { modal: true },
        'Clear',
      );
      if (confirm === 'Clear' && historyManager) {
        await historyManager.clearHistory();
        historyViewProvider?.refresh();
        vscode.window.showInformationMessage('PasteShield history cleared.');
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_HISTORY_JSON_COMMAND_ID, async () => {
      if (!historyManager) return;
      await exportHistory('json');
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_HISTORY_TEXT_COMMAND_ID, async () => {
      if (!historyManager) return;
      await exportHistory('text');
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(REFRESH_HISTORY_COMMAND_ID, () => {
      historyViewProvider?.refresh();
    }),
  );

  // Statistics Dashboard command
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_STATISTICS_COMMAND_ID, async () => {
      if (!statisticsManager) {
        vscode.window.showWarningMessage('Statistics manager not initialized.');
        return;
      }
      await showStatisticsDashboard();
    }),
  );

  // Export Audit Log command
  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_AUDIT_LOG_COMMAND_ID, async () => {
      if (!historyManager) {
        vscode.window.showWarningMessage('History manager not initialized.');
        return;
      }
      await exportAuditLog();
    }),
  );

  // Show Rotation Reminders command
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_ROTATION_REMINDERS_COMMAND_ID, async () => {
      await showRotationReminders();
    }),
  );

  // Add to Workspace Ignore command
  context.subscriptions.push(
    vscode.commands.registerCommand(ADD_TO_WORKSPACE_IGNORE_COMMAND_ID, async (pattern?: string) => {
      if (!ignorePatternsManager) {
        vscode.window.showWarningMessage('Ignore patterns manager not initialized.');
        return;
      }
      
      if (pattern) {
        await ignorePatternsManager.addToWorkspaceIgnore(pattern);
      } else {
        // Prompt user for pattern
        const input = await vscode.window.showInputBox({
          prompt: 'Enter the pattern name to add to workspace ignore list',
          placeHolder: 'e.g., AWS Access Key ID',
        });
        if (input) {
          await ignorePatternsManager.addToWorkspaceIgnore(input);
        }
      }
    }),
  );

  // Watch for workspace file changes to refresh ignore patterns
  const fileWatcher = vscode.workspace.createFileSystemWatcher('**/{.pasteshieldignore,.gitignore}');
  context.subscriptions.push(
    fileWatcher.onDidChange(() => {
      ignorePatternsManager?.refresh();
    }),
    fileWatcher.onDidCreate(() => {
      ignorePatternsManager?.refresh();
    }),
    fileWatcher.onDidDelete(() => {
      ignorePatternsManager?.refresh();
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration(CONFIG_SECTION)) {
        updateStatusBar(getConfig().enabled);
        codeLensProvider?.refresh();
        historyViewProvider?.refresh();
        ignorePatternsManager?.refresh();
      }
    }),
  );

  // Re-scan open documents when they change (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(() => {
      debouncedRefreshCodeLens();
    }),
  );

  // Refresh CodeLens when a new editor becomes active
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(() => {
      debouncedRefreshCodeLens();
    }),
  );

  // Clear decorations when editor closes
  context.subscriptions.push(
    vscode.window.onDidChangeVisibleTextEditors(() => {
      debouncedPruneDecorations();
    }),
  );

  context.subscriptions.push(statusBarItem);
  Object.values(decorationTypes).forEach(dt => context.subscriptions.push(dt));

  statusBarItem.show();
  logger.info('PasteShield: activated');
}

// ─── Core Paste Handler ────────────────────────────────────────────────────────

async function handlePaste(): Promise<void> {
  const config = getConfig();

  // Fast path: feature disabled → delegate immediately
  if (!config.enabled) {
    await executeFallbackPaste();
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    await executeFallbackPaste();
    return;
  }

  // ── .env / .env.local exception ───────────────────────────────────────────
  // These files are intentionally used to store secrets locally. PasteShield
  // should not intercept paste operations in them. CodeLens still runs on
  // existing file content to surface any secrets that are already present.
  if (isPasteExcludedFile(editor.document)) {
    logger.info(
      `PasteShield: paste interception skipped for excluded file "${path.basename(editor.document.fileName)}"`,
    );
    await executeFallbackPaste();
    return;
  }

  // Respect ignored languages
  if (config.ignoredLanguages.includes(editor.document.languageId)) {
    await executeFallbackPaste();
    return;
  }

  // Read clipboard
  let clipboardText: string;
  try {
    clipboardText = await vscode.env.clipboard.readText();
  } catch (err) {
    logger.error('PasteShield: clipboard read failed', err);
    await executeFallbackPaste();
    return;
  }

  if (!clipboardText || clipboardText.trim().length === 0) {
    await executeFallbackPaste();
    return;
  }

  // Scan asynchronously to avoid blocking the UI thread
  const detections = await runScanAsync(clipboardText, {
    ignoredPatterns: config.ignoredPatterns,
  });

  // Filter by minimum severity
  const filtered = detections.filter(d =>
    meetsSeverityThreshold(d.severity, config.minimumSeverity),
  );

  if (filtered.length === 0) {
    await executeFallbackPaste();
    return;
  }

  // Persist report for "Show Details" / status bar command
  lastReport = filtered;

  // Silent mode: log to history without blocking paste
  if (config.silentMode) {
    logger.info(`PasteShield: silent mode - logged ${filtered.length} issue(s) to history`);
    
    // Add to history silently
    if (historyManager) {
      await historyManager.addEntry({
        fileName: editor.document.fileName,
        detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
        actionTaken: 'pasted_silent',
      });
      historyViewProvider?.refresh();
    }
    
    // Still paste the content without blocking
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, filtered[0].severity);
    }
    debouncedRefreshCodeLens();
    return;
  }

  // Build warning
  const topSeverity = filtered[0].severity; // already sorted by severity

  const summary = buildSummaryMessage(filtered);

  const choice = await vscode.window.showWarningMessage(
    `PasteShield: ${summary}`,
    'Paste Anyway',
    'Show Details',
    'Report False Positive',
    'Cancel',
  );

  if (choice === 'Paste Anyway') {
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, topSeverity);
    }
    // Trigger a CodeLens refresh so the pasted secrets are highlighted
    debouncedRefreshCodeLens();
    logger.info(`PasteShield: user bypassed warning (${filtered.length} issue(s))`);
    
    // Add to history
    if (historyManager) {
      await historyManager.addEntry({
        fileName: editor.document.fileName,
        detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
        actionTaken: 'pasted',
      });
      historyViewProvider?.refresh();
    }
    return;
  }

  if (choice === 'Report False Positive') {
    await reportFalsePositive(filtered, ignorePatternsManager);
    // After reporting, paste the content
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, topSeverity);
    }
    debouncedRefreshCodeLens();
    logger.info('PasteShield: false positive reported and pasted');
    return;
  }

  if (choice === 'Show Details') {
    await showDetailsPanel(filtered);
    // Re-prompt with modal for a deliberate second confirmation
    const finalChoice = await vscode.window.showWarningMessage(
      `PasteShield — ${filtered.length} issue(s) found. Paste anyway?`,
      { modal: true },
      'Paste Anyway',
    );
    if (finalChoice === 'Paste Anyway') {
      const insertRange = await insertText(editor, clipboardText);
      if (insertRange && config.showInlineDecorations) {
        applyDecoration(editor, insertRange, topSeverity);
      }
      debouncedRefreshCodeLens();
      logger.info('PasteShield: user bypassed warning after details review');
      
      // Add to history
      if (historyManager) {
        await historyManager.addEntry({
          fileName: editor.document.fileName,
          detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
          actionTaken: 'pasted',
        });
        historyViewProvider?.refresh();
      }
    } else {
      logger.info('PasteShield: paste cancelled after details review');
      
      // Add to history
      if (historyManager) {
        await historyManager.addEntry({
          fileName: editor.document.fileName,
          detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
          actionTaken: 'cancelled',
        });
        historyViewProvider?.refresh();
      }
    }
    return;
  }

  // 'Cancel' or dismissed → do nothing
  logger.info('PasteShield: paste cancelled by user');
  
  // Add to history
  if (historyManager) {
    await historyManager.addEntry({
      fileName: editor.document.fileName,
      detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
      actionTaken: 'cancelled',
    });
    historyViewProvider?.refresh();
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Runs the scan in a microtask yield so it doesn't block the event loop.
 */
function runScanAsync(
  text: string,
  options: { ignoredPatterns: string[] },
): Promise<DetectionResult[]> {
  return new Promise(resolve => {
    // setTimeout(0) yields to allow any pending UI updates first
    setTimeout(() => {
      const start = performance.now();
      const results = scanContent(text, options);
      const elapsed = performance.now() - start;
      if (elapsed > 50) {
        logger.warn(`PasteShield: scan took ${elapsed.toFixed(1)} ms (> 50 ms threshold)`);
      }
      resolve(results);
    }, 0);
  });
}

/**
 * Delegates to VS Code's built-in paste via edit builder.
 */
async function executeFallbackPaste(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return;
  }

  const text = await vscode.env.clipboard.readText();
  if (!text) {
    return;
  }

  await editor.edit(editBuilder => {
    for (const selection of editor.selections) {
      if (selection.isEmpty) {
        editBuilder.insert(selection.active, text);
      } else {
        editBuilder.replace(selection, text);
      }
    }
  });
}

/**
 * Inserts `text` at the current cursor position(s), replacing selections.
 * Returns the range of the first insertion for decoration purposes.
 */
async function insertText(
  editor: vscode.TextEditor,
  text: string,
): Promise<vscode.Range | undefined> {
  let firstRange: vscode.Range | undefined;

  const success = await editor.edit(editBuilder => {
    for (const selection of editor.selections) {
      if (selection.isEmpty) {
        editBuilder.insert(selection.active, text);
        if (!firstRange) {
          firstRange = new vscode.Range(selection.active, selection.active);
        }
      } else {
        editBuilder.replace(selection, text);
        if (!firstRange) {
          firstRange = selection;
        }
      }
    }
  });

  if (!success) {
    logger.error('PasteShield: edit failed — document may be read-only');
    vscode.window.showErrorMessage(
      'PasteShield: Could not paste — document may be read-only.',
    );
  }

  return firstRange;
}

/**
 * Builds a short human-readable summary for the warning message.
 */
function buildSummaryMessage(detections: DetectionResult[]): string {
  const uniqueTypes = [...new Set(detections.map(d => d.type))];
  const countStr = detections.length === 1 ? '1 issue' : `${detections.length} issues`;

  if (uniqueTypes.length === 1) {
    return `${detections[0].description} (${countStr})`;
  }

  const preview = uniqueTypes.slice(0, 2).join(', ');
  const more    = uniqueTypes.length > 2 ? ` +${uniqueTypes.length - 2} more` : '';
  return `${countStr} detected — ${preview}${more}`;
}

/**
 * Opens a side panel with a formatted security report.
 */
async function showDetailsPanel(detections: DetectionResult[]): Promise<void> {
  const lines: string[] = [
    `Date: ${new Date().toLocaleString()}`,
    `Generated by DevToolkit's PasteShield`,
    '╔══════════════════════════════════════════════════════╗',
    '║          PasteShield — Security Scan Report          ║',
    '╚══════════════════════════════════════════════════════╝',
    '',
    `Issues found: ${detections.length}`,
    '',
    '─'.repeat(56),
    '',
  ];

  for (const [i, det] of detections.entries()) {
    const sevLabel  = det.severity.toUpperCase().padEnd(8);
    const lineInfo  = det.line !== undefined ? ` (line ${det.line})` : '';
    const catLabel  = det.category ? ` [${det.category}]` : '';
    lines.push(`[${i + 1}] ${sevLabel} — ${det.type}${catLabel}${lineInfo}`);
    lines.push(`     ${det.description}`);
    lines.push(`     Match: ${det.match}`);
    lines.push('');
  }

  lines.push('─'.repeat(56));
  lines.push('');
  lines.push('To suppress a pattern, add its name to:');
  lines.push('  pasteShield.ignoredPatterns  (settings.json)');
  lines.push('');
  lines.push('Files excluded from paste interception:');
  lines.push('  .env, .env.local');

  const doc = await vscode.workspace.openTextDocument({
    content: lines.join('\n'),
    language: 'plaintext',
  });

  await vscode.window.showTextDocument(doc, {
    preview:       true,
    viewColumn:    vscode.ViewColumn.Beside,
    preserveFocus: false,
  });
}

/**
 * Adds `patternName` to the `pasteShield.ignoredPatterns` setting globally.
 */
async function addToIgnoredPatterns(patternName: string): Promise<void> {
  const config  = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const current = config.get<string[]>('ignoredPatterns', []);

  if (current.includes(patternName)) {
    vscode.window.showInformationMessage(
      `PasteShield: "${patternName}" is already ignored.`,
    );
    return;
  }

  await config.update(
    'ignoredPatterns',
    [...current, patternName],
    vscode.ConfigurationTarget.Global,
  );

  vscode.window.showInformationMessage(
    `PasteShield: Pattern "${patternName}" added to ignored list.`,
  );
}

/**
 * Reports a false positive by adding detected patterns to the ignored list.
 */
async function reportFalsePositive(
  detections: DetectionResult[],
  ignorePatternsManager?: IgnorePatternsManager,
): Promise<void> {
  if (detections.length === 0) {
    return;
  }

  // Get unique pattern types from detections
  const patternTypes = [...new Set(detections.map(d => d.type))];
  
  if (patternTypes.length === 1) {
    // Single pattern type - add it directly
    const patternName = patternTypes[0];
    if (ignorePatternsManager) {
      await ignorePatternsManager.addToWorkspaceIgnore(patternName);
    } else {
      await addToIgnoredPatterns(patternName);
    }
  } else {
    // Multiple pattern types - let user choose which to ignore
    const selected = await vscode.window.showQuickPick(
      patternTypes.map(p => ({ label: p, description: 'Add to ignored patterns' })),
      {
        placeHolder: 'Select patterns to mark as false positives',
        canPickMany: true,
      }
    );

    if (selected && selected.length > 0) {
      for (const item of selected) {
        if (ignorePatternsManager) {
          await ignorePatternsManager.addToWorkspaceIgnore(item.label);
        } else {
          await addToIgnoredPatterns(item.label);
        }
      }
      vscode.window.showInformationMessage(
        `PasteShield: ${selected.length} pattern(s) marked as false positive(s).`,
      );
    }
  }
}

/**
 * Applies a short-lived inline decoration at `range` in `editor`.
 * Auto-clears after 10 seconds.
 */
function applyDecoration(
  editor: vscode.TextEditor,
  range: vscode.Range,
  severity: Severity,
): void {
  if (!decorationTypes) {
    return;
  }
  const dt = decorationTypes[severity];
  editor.setDecorations(dt, [range]);
  activeDecorations.push({ editor, type: dt });

  setTimeout(() => {
    editor.setDecorations(dt, []);
    activeDecorations = activeDecorations.filter(
      d => !(d.editor === editor && d.type === dt),
    );
  }, 10_000);
}

/**
 * Removes decorations for editors that are no longer visible.
 */
function pruneStaleDecorations(): void {
  const visibleEditors = new Set(vscode.window.visibleTextEditors);
  activeDecorations = activeDecorations.filter(({ editor, type }) => {
    if (!visibleEditors.has(editor)) {
      editor.setDecorations(type, []);
      return false;
    }
    return true;
  });
}

// ─── Toggle & Status Bar ──────────────────────────────────────────────────────

function updateStatusBar(enabled: boolean): void {
  if (!statusBarItem) {
    return;
  }
  if (enabled) {
    statusBarItem.text            = '$(shield)';
    statusBarItem.tooltip         = 'PasteShield is active — click to toggle or view last report';
    statusBarItem.color           = undefined;
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text            = '$(shield)';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.tooltip         = 'PasteShield is disabled — click to enable';
    statusBarItem.color           = new vscode.ThemeColor('statusBarItem.warningForeground');
  }
  statusBarItem.command = TOGGLE_COMMAND_ID;
}

async function togglePasteShield(): Promise<void> {
  const config  = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const current = config.get<boolean>('enabled', true);
  await config.update('enabled', !current, vscode.ConfigurationTarget.Global);
  const next = !current;
  updateStatusBar(next);
  // Refresh CodeLens to hide/show lenses based on the new enabled state
  codeLensProvider?.refresh();
  vscode.window.withProgress(
    {
      location:    vscode.ProgressLocation.Notification,
      title:       `PasteShield ${next ? 'enabled' : 'disabled'}.`,
      cancellable: false,
    },
    () => new Promise<void>(resolve => setTimeout(resolve, 2500)),
  );
}

async function exportHistory(format: 'json' | 'text'): Promise<void> {
  if (!historyManager) {
    vscode.window.showWarningMessage('History manager not initialized.');
    return;
  }

  const content = format === 'json' 
    ? historyManager.exportAsJson() 
    : historyManager.exportAsText();
  
  const extension = format === 'json' ? 'json' : 'txt';
  const defaultFileName = `pasteshield-history-${new Date().toISOString().split('T')[0]}.${extension}`;

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(defaultFileName),
    filters: {
      [format.toUpperCase()]: [extension],
    },
  });

  if (uri) {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
    vscode.window.showInformationMessage(`History exported to ${uri.fsPath}`);
  }
}

async function showLastReport(): Promise<void> {
  if (lastReport.length === 0) {
    vscode.window.withProgress(
      {
        location:    vscode.ProgressLocation.Notification,
        title:       'PasteShield: No scan report available yet.',
        cancellable: false,
      },
      () => new Promise<void>(resolve => setTimeout(resolve, 2500)),
    );
    return;
  }
  await showDetailsPanel(lastReport);
}

/**
 * Show statistics dashboard in a side panel
 */
async function showStatisticsDashboard(): Promise<void> {
  if (!statisticsManager) return;

  const report = statisticsManager.generateReport();
  
  const doc = await vscode.workspace.openTextDocument({
    content: report,
    language: 'plaintext',
  });

  await vscode.window.showTextDocument(doc, {
    preview: true,
    viewColumn: vscode.ViewColumn.Beside,
    preserveFocus: false,
  });
}

/**
 * Export audit log for compliance reporting
 */
async function exportAuditLog(): Promise<void> {
  if (!historyManager) return;

  const config = vscode.workspace.getConfiguration('pasteShield');
  const enableAuditLogging = config.get<boolean>('enableAuditLogging', true);
  
  if (!enableAuditLogging) {
    vscode.window.showWarningMessage('Audit logging is disabled. Enable it in settings to export audit logs.');
    return;
  }

  const history = historyManager.getHistory();
  const auditEntries = history.map(entry => ({
    timestamp: new Date(entry.timestamp).toISOString(),
    file: entry.fileName,
    action: entry.actionTaken,
    detectionCount: entry.detections.length,
    detections: entry.detections.map(d => ({
      type: d.type,
      severity: d.severity,
      category: d.category,
    })),
  }));

  const content = JSON.stringify({
    generatedAt: new Date().toISOString(),
    version: '1.0',
    totalEntries: auditEntries.length,
    entries: auditEntries,
  }, null, 2);

  const defaultFileName = `pasteshield-audit-log-${new Date().toISOString().split('T')[0]}.json`;

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(defaultFileName),
    filters: {
      JSON: ['json'],
    },
  });

  if (uri) {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
    vscode.window.showInformationMessage(`Audit log exported to ${uri.fsPath}`);
  }
}

/**
 * Show secret rotation reminders for detected credentials
 */
async function showRotationReminders(): Promise<void> {
  if (!historyManager) return;

  const config = vscode.workspace.getConfiguration('pasteShield');
  const reminderDays = config.get<number>('secretRotationReminderDays', 90);
  
  const history = historyManager.getHistory();
  const now = Date.now();
  // @ts-ignore TS6133 - Calculated for future reminder logic implementation
  const _reminderThreshold = reminderDays * 24 * 60 * 60 * 1000;

  // Group detections by type and find the oldest occurrence
  const oldestDetections: Record<string, { timestamp: number; severity: string; category?: string }> = {};

  for (const entry of history) {
    if (entry.actionTaken !== 'pasted') continue;

    for (const det of entry.detections) {
      const key = `${det.type}-${det.category || 'unknown'}`;
      if (!oldestDetections[key] || entry.timestamp < oldestDetections[key].timestamp) {
        oldestDetections[key] = {
          timestamp: entry.timestamp,
          severity: det.severity,
          category: det.category,
        };
      }
    }
  }

  // Find secrets that need rotation
  const needsRotation: Array<{ type: string; category?: string; daysSinceDetection: number; severity: string }> = [];

  for (const [key, data] of Object.entries(oldestDetections)) {
    const daysSince = Math.floor((now - data.timestamp) / (24 * 60 * 60 * 1000));
    if (daysSince >= reminderDays) {
      const [type, category] = key.split('-');
      needsRotation.push({
        type: type.replace(/-/g, ' '),
        category: category !== 'unknown' ? category : undefined,
        daysSinceDetection: daysSince,
        severity: data.severity,
      });
    }
  }

  if (needsRotation.length === 0) {
    vscode.window.showInformationMessage(
      `🎉 All detected secrets have been rotated recently!\\n\\nNo secrets older than ${reminderDays} days found.`
    );
    return;
  }

  // Sort by severity and days since detection
  needsRotation.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (severityOrder[a.severity as keyof typeof severityOrder] !== severityOrder[b.severity as keyof typeof severityOrder]) {
      return severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder];
    }
    return b.daysSinceDetection - a.daysSinceDetection;
  });

  const message = `⚠️ Secret Rotation Reminders\\n\\n` +
    `The following secrets were detected ${reminderDays}+ days ago and should be rotated:\\n\\n` +
    needsRotation.slice(0, 10).map(s => 
      `• ${s.type}${s.category ? ` (${s.category})` : ''} - ${s.daysSinceDetection} days ago [${s.severity.toUpperCase()}]`
    ).join('\\n') +
    (needsRotation.length > 10 ? `\\n\\n...and ${needsRotation.length - 10} more` : '');

  const choice = await vscode.window.showWarningMessage(message, { modal: true }, 'Rotate Now', 'Dismiss');
  
  if (choice === 'Rotate Now') {
    await vscode.env.openExternal(vscode.Uri.parse('https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/rotating-secrets'));
  }
}