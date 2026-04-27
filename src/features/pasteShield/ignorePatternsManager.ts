/**
 * PasteShield — Ignore Patterns Manager
 * 
 * Manages workspace-level and user-level ignore patterns.
 * Supports .gitignore-style pattern files for flexible configuration.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { minimatch } from 'minimatch';

const WORKSPACE_IGNORE_FILE = '.pasteshieldignore';
const CONFIG_SECTION = 'pasteShield';

export interface IgnorePattern {
  pattern: string;
  source: 'user' | 'workspace' | 'gitignore';
  line?: number;
}

export class IgnorePatternsManager {
  private static instance: IgnorePatternsManager | undefined;
  // @ts-ignore TS6133 - Stored for potential future use
  private _context: vscode.ExtensionContext;
  private workspacePatterns: IgnorePattern[] = [];
  private gitignorePatterns: string[] = [];

  private constructor(context: vscode.ExtensionContext) {
    this._context = context;
    this.loadWorkspacePatterns();
    this.loadGitignorePatterns();
  }

  public static getInstance(context: vscode.ExtensionContext): IgnorePatternsManager {
    if (!IgnorePatternsManager.instance) {
      IgnorePatternsManager.instance = new IgnorePatternsManager(context);
    }
    return IgnorePatternsManager.instance;
  }

  /**
   * Load patterns from workspace .pasteshieldignore file
   */
  private loadWorkspacePatterns(): void {
    this.workspacePatterns = [];
    
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) return;

    for (const folder of workspaceFolders) {
      const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
      
      try {
        if (fs.existsSync(ignoreFilePath)) {
          const content = fs.readFileSync(ignoreFilePath, 'utf-8');
          const lines = content.split('\n');
          
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Skip empty lines and comments
            if (!line || line.startsWith('#')) continue;
            
            this.workspacePatterns.push({
              pattern: line,
              source: 'workspace',
              line: i + 1,
            });
          }
        }
      } catch (error) {
        console.error(`Error loading workspace ignore file: ${ignoreFilePath}`, error);
      }
    }
  }

  /**
   * Load patterns from .gitignore file
   */
  private loadGitignorePatterns(): void {
    this.gitignorePatterns = [];
    
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) return;

    for (const folder of workspaceFolders) {
      const gitignorePath = path.join(folder.uri.fsPath, '.gitignore');
      
      try {
        if (fs.existsSync(gitignorePath)) {
          const content = fs.readFileSync(gitignorePath, 'utf-8');
          const lines = content.split('\n');
          
          for (const line of lines) {
            const trimmed = line.trim();
            // Skip empty lines and comments
            if (!trimmed || trimmed.startsWith('#')) continue;
            
            // Only add patterns that look like they might match secret files
            if (this.isRelevantGitignorePattern(trimmed)) {
              this.gitignorePatterns.push(trimmed);
            }
          }
        }
      } catch (error) {
        console.error(`Error loading .gitignore file: ${gitignorePath}`, error);
      }
    }
  }

  /**
   * Check if a gitignore pattern is relevant for secret detection
   */
  private isRelevantGitignorePattern(pattern: string): boolean {
    const secretRelatedKeywords = [
      '.env', 'secret', 'key', 'token', 'credential', 'password',
      'auth', 'private', 'pem', 'cert', 'ssl', 'ssh'
    ];
    
    const lowerPattern = pattern.toLowerCase();
    return secretRelatedKeywords.some(keyword => lowerPattern.includes(keyword));
  }

  /**
   * Get all ignore patterns (user + workspace + gitignore)
   */
  public getAllPatterns(): IgnorePattern[] {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const userPatterns = config.get<string[]>('ignoredPatterns', [])
      .map(pattern => ({ pattern, source: 'user' as const }));

    return [...userPatterns, ...this.workspacePatterns];
  }

  /**
   * Check if a pattern should be ignored
   */
  public shouldIgnore(patternName: string, filePath?: string): boolean {
    const allPatterns = this.getAllPatterns();
    
    for (const { pattern } of allPatterns) {
      if (this.matchesPattern(patternName, pattern, filePath)) {
        return true;
      }
    }
    
    // Also check gitignore patterns if file path is provided
    if (filePath) {
      for (const gitPattern of this.gitignorePatterns) {
        if (minimatch(filePath, gitPattern, { dot: true })) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Check if a pattern name matches an ignore pattern
   */
  private matchesPattern(patternName: string, ignorePattern: string, _filePath?: string): boolean {
    // Exact match
    if (patternName === ignorePattern) {
      return true;
    }
    
    // Glob pattern match
    if (ignorePattern.includes('*') || ignorePattern.includes('?')) {
      if (minimatch(patternName, ignorePattern)) {
        return true;
      }
    }
    
    // Partial match (substring)
    if (patternName.toLowerCase().includes(ignorePattern.toLowerCase())) {
      return true;
    }
    
    return false;
  }

  /**
   * Add a pattern to workspace ignore file
   */
  public async addToWorkspaceIgnore(pattern: string): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      vscode.window.showWarningMessage('No workspace folder open to save ignore pattern.');
      return;
    }

    const folder = workspaceFolders[0];
    const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
    
    try {
      let content = '';
      if (fs.existsSync(ignoreFilePath)) {
        content = fs.readFileSync(ignoreFilePath, 'utf-8');
        // Check if pattern already exists
        if (content.split('\n').some(line => line.trim() === pattern)) {
          vscode.window.showInformationMessage(`Pattern "${pattern}" is already in ${WORKSPACE_IGNORE_FILE}`);
          return;
        }
        content = content.trimEnd() + '\n';
      }
      
      content += `# Added by PasteShield on ${new Date().toLocaleString()}\n${pattern}\n`;
      
      fs.writeFileSync(ignoreFilePath, content, 'utf-8');
      this.loadWorkspacePatterns(); // Reload patterns
      
      vscode.window.showInformationMessage(`Added "${pattern}" to ${WORKSPACE_IGNORE_FILE}`);
    } catch (error) {
      vscode.window.showErrorMessage(`Failed to write to ${WORKSPACE_IGNORE_FILE}: ${error}`);
    }
  }

  /**
   * Remove a pattern from workspace ignore file
   */
  public async removeFromWorkspaceIgnore(pattern: string): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) return;

    const folder = workspaceFolders[0];
    const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
    
    try {
      if (!fs.existsSync(ignoreFilePath)) return;
      
      const content = fs.readFileSync(ignoreFilePath, 'utf-8');
      const lines = content.split('\n');
      const newLines = lines.filter((line: string) => line.trim() !== pattern);
      
      fs.writeFileSync(ignoreFilePath, newLines.join('\n'), 'utf-8');
      this.loadWorkspacePatterns(); // Reload patterns
      
      vscode.window.showInformationMessage(`Removed "${pattern}" from ${WORKSPACE_IGNORE_FILE}`);
    } catch (error) {
      vscode.window.showErrorMessage(`Failed to update ${WORKSPACE_IGNORE_FILE}: ${error}`);
    }
  }

  /**
   * Refresh patterns (e.g., after file changes)
   */
  public refresh(): void {
    this.loadWorkspacePatterns();
    this.loadGitignorePatterns();
  }

  /**
   * Get patterns by source
   */
  public getPatternsBySource(): {
    user: IgnorePattern[];
    workspace: IgnorePattern[];
    gitignore: string[];
  } {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const userPatterns = config.get<string[]>('ignoredPatterns', [])
      .map(pattern => ({ pattern, source: 'user' as const }));

    return {
      user: userPatterns,
      workspace: this.workspacePatterns,
      gitignore: this.gitignorePatterns,
    };
  }
}
