/**
 * PasteShield — Custom User Patterns Manager
 * 
 * Allows users to define custom regex patterns with severity levels via settings.
 * Patterns are stored in VS Code configuration and integrated into the scanning engine.
 */

import * as vscode from 'vscode';

const CONFIG_SECTION = 'pasteShield';

export interface CustomPattern {
  name: string;
  regex: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  category: string;
  enabled: boolean;
}

export interface CustomPatternDefinition {
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  category: string;
  redact: boolean;
}

export class CustomPatternsManager {
  private static instance: CustomPatternsManager | undefined;
  // @ts-ignore TS6133 - Stored for future extensibility
  private _context: vscode.ExtensionContext;
  private customPatterns: CustomPattern[] = [];
  private compiledPatterns: Map<string, CustomPatternDefinition> = new Map();

  private constructor(context: vscode.ExtensionContext) {
    this._context = context;
    this.loadCustomPatterns();
  }

  public static getInstance(context: vscode.ExtensionContext): CustomPatternsManager {
    if (!CustomPatternsManager.instance) {
      CustomPatternsManager.instance = new CustomPatternsManager(context);
    }
    return CustomPatternsManager.instance;
  }

  /**
   * Load custom patterns from VS Code configuration
   */
  private loadCustomPatterns(): void {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const patterns = config.get<CustomPattern[]>('customPatterns', []);
    
    this.customPatterns = patterns.filter(p => p.enabled !== false);
    this.compilePatterns();
  }

  /**
   * Compile regex patterns and cache them
   */
  private compilePatterns(): void {
    this.compiledPatterns.clear();
    
    for (const pattern of this.customPatterns) {
      try {
        const regex = new RegExp(pattern.regex, 'g');
        this.compiledPatterns.set(pattern.name, {
          name: pattern.name,
          regex,
          severity: pattern.severity,
          description: pattern.description || 'Custom user-defined pattern',
          category: pattern.category || 'Custom',
          redact: true,
        });
      } catch (error) {
        console.error(`Failed to compile custom pattern "${pattern.name}":`, error);
        vscode.window.showWarningMessage(
          `Custom pattern "${pattern.name}" has an invalid regex and will be skipped.`
        );
      }
    }
  }

  /**
   * Get all compiled custom pattern definitions
   */
  public getCompiledPatterns(): CustomPatternDefinition[] {
    return Array.from(this.compiledPatterns.values());
  }

  /**
   * Add a new custom pattern
   */
  public async addPattern(pattern: CustomPattern): Promise<void> {
    // Validate regex before saving
    try {
      new RegExp(pattern.regex);
    } catch (error) {
      vscode.window.showErrorMessage(`Invalid regex pattern: ${(error as Error).message}`);
      return;
    }

    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const currentPatterns = config.get<CustomPattern[]>('customPatterns', []);
    
    // Check for duplicate name
    if (currentPatterns.some(p => p.name === pattern.name)) {
      vscode.window.showWarningMessage(`A pattern named "${pattern.name}" already exists.`);
      return;
    }

    const newPatterns = [...currentPatterns, pattern];
    await config.update('customPatterns', newPatterns, vscode.ConfigurationTarget.Global);
    
    this.loadCustomPatterns();
    vscode.window.showInformationMessage(`Custom pattern "${pattern.name}" added successfully.`);
  }

  /**
   * Remove a custom pattern by name
   */
  public async removePattern(name: string): Promise<void> {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const currentPatterns = config.get<CustomPattern[]>('customPatterns', []);
    
    const newPatterns = currentPatterns.filter(p => p.name !== name);
    await config.update('customPatterns', newPatterns, vscode.ConfigurationTarget.Global);
    
    this.loadCustomPatterns();
    vscode.window.showInformationMessage(`Custom pattern "${name}" removed.`);
  }

  /**
   * Enable or disable a custom pattern
   */
  public async togglePattern(name: string, enabled: boolean): Promise<void> {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const currentPatterns = config.get<CustomPattern[]>('customPatterns', []);
    
    const updatedPatterns = currentPatterns.map(p => 
      p.name === name ? { ...p, enabled } : p
    );
    
    await config.update('customPatterns', updatedPatterns, vscode.ConfigurationTarget.Global);
    this.loadCustomPatterns();
  }

  /**
   * Edit an existing custom pattern
   */
  public async editPattern(oldName: string, newPattern: CustomPattern): Promise<void> {
    // Validate regex
    try {
      new RegExp(newPattern.regex);
    } catch (error) {
      vscode.window.showErrorMessage(`Invalid regex pattern: ${(error as Error).message}`);
      return;
    }

    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const currentPatterns = config.get<CustomPattern[]>('customPatterns', []);
    
    const index = currentPatterns.findIndex(p => p.name === oldName);
    if (index === -1) {
      vscode.window.showErrorMessage(`Pattern "${oldName}" not found.`);
      return;
    }

    currentPatterns[index] = newPattern;
    await config.update('customPatterns', currentPatterns, vscode.ConfigurationTarget.Global);
    
    this.loadCustomPatterns();
    vscode.window.showInformationMessage(`Custom pattern "${newPattern.name}" updated.`);
  }

  /**
   * Import patterns from JSON
   */
  public async importPatterns(jsonContent: string): Promise<void> {
    try {
      const importedPatterns: CustomPattern[] = JSON.parse(jsonContent);
      
      if (!Array.isArray(importedPatterns)) {
        throw new Error('Imported data must be an array of patterns');
      }

      // Validate each pattern
      for (const pattern of importedPatterns) {
        if (!pattern.name || !pattern.regex || !pattern.severity) {
          throw new Error('Each pattern must have name, regex, and severity');
        }
        new RegExp(pattern.regex); // Validate regex
      }

      const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
      const currentPatterns = config.get<CustomPattern[]>('customPatterns', []);
      
      // Merge patterns, avoiding duplicates by name
      const mergedPatterns = [...currentPatterns];
      for (const imported of importedPatterns) {
        const existingIndex = mergedPatterns.findIndex(p => p.name === imported.name);
        if (existingIndex >= 0) {
          mergedPatterns[existingIndex] = imported;
        } else {
          mergedPatterns.push(imported);
        }
      }

      await config.update('customPatterns', mergedPatterns, vscode.ConfigurationTarget.Global);
      this.loadCustomPatterns();
      
      vscode.window.showInformationMessage(
        `Successfully imported ${importedPatterns.length} custom pattern(s).`
      );
    } catch (error) {
      vscode.window.showErrorMessage(`Failed to import patterns: ${(error as Error).message}`);
    }
  }

  /**
   * Export patterns to JSON
   */
  public exportPatterns(): string {
    return JSON.stringify(this.customPatterns, null, 2);
  }

  /**
   * Refresh patterns from configuration
   */
  public refresh(): void {
    this.loadCustomPatterns();
  }

  /**
   * Get pattern by name
   */
  public getPattern(name: string): CustomPattern | undefined {
    return this.customPatterns.find(p => p.name === name);
  }

  /**
   * Get all custom patterns
   */
  public getAllPatterns(): CustomPattern[] {
    return [...this.customPatterns];
  }
}

/**
 * Scan text against custom patterns
 */
export function scanWithCustomPatterns(
  text: string,
  patterns: CustomPatternDefinition[]
): Array<{
  type: string;
  description: string;
  match: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line?: number;
  category: string;
}> {
  const results: Array<{
    type: string;
    description: string;
    match: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    line?: number;
    category: string;
  }> = [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    const match = regex.exec(text);

    if (match) {
      const rawMatch = match[0];
      const displayMatch = pattern.redact ? redactMatch(rawMatch) : truncateMatch(rawMatch);

      results.push({
        type: pattern.name,
        description: pattern.description,
        match: displayMatch,
        severity: pattern.severity,
        line: getLineNumber(text, match.index),
        category: pattern.category,
      });
    }
  }

  return results;
}

function redactMatch(match: string): string {
  if (match.length <= 8) {
    return match.substring(0, 2) + '***';
  }
  return match.substring(0, 4) + '...' + match.substring(match.length - 4);
}

function truncateMatch(match: string, maxLength: number = 50): string {
  if (match.length <= maxLength) {
    return match;
  }
  return match.substring(0, maxLength - 3) + '...';
}

function getLineNumber(text: string, index: number): number {
  const lines = text.substring(0, index).split('\n');
  return lines.length;
}