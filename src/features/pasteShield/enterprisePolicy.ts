/**
 * PasteShield — Enterprise Policy Enforcement
 * 
 * Provides team-wide policy enforcement for enterprise deployments.
 * Supports centralized policy configuration, compliance rules, and team management.
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

const CONFIG_SECTION = 'pasteShield';

export interface EnterprisePolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: PolicyRule[];
  enforcedAt?: number;
  version: string;
}

export interface PolicyRule {
  id: string;
  type: 'block_pattern' | 'require_encryption' | 'audit_logging' | 'rotation_policy' | 'allowed_categories';
  severity: 'critical' | 'high' | 'medium' | 'low';
  patternNames?: string[];
  categories?: string[];
  action: 'block' | 'warn' | 'audit' | 'encrypt';
  message?: string;
  exceptions?: string[]; // File patterns or user groups that are exempt
}

export interface TeamMember {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'developer' | 'auditor';
  groups: string[];
}

export interface ComplianceReport {
  generatedAt: string;
  period: { start: string; end: string };
  totalScans: number;
  policyViolations: number;
  blockedPastes: number;
  warningsIssued: number;
  criticalDetections: number;
  highDetections: number;
  mediumDetections: number;
  lowDetections: number;
  topViolators: Array<{ user: string; violations: number }>;
  topDetectedTypes: Array<{ type: string; count: number }>;
  complianceScore: number;
}

export class EnterprisePolicyManager {
  private static instance: EnterprisePolicyManager | undefined;
  private context: vscode.ExtensionContext;
  private currentPolicy: EnterprisePolicy | null = null;
  private policyFilePath: string = '';
  // @ts-ignore TS6133 - Loaded from configuration, kept for policy management
  private teamMembers: TeamMember[] = [];

  private constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.policyFilePath = this.getPolicyFilePath();
    this.loadPolicy();
    this.loadTeamMembers();
  }

  public static getInstance(context: vscode.ExtensionContext): EnterprisePolicyManager {
    if (!EnterprisePolicyManager.instance) {
      EnterprisePolicyManager.instance = new EnterprisePolicyManager(context);
    }
    return EnterprisePolicyManager.instance;
  }

  /**
   * Get the policy file path (workspace-level or global)
   */
  private getPolicyFilePath(): string {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
      return path.join(workspaceFolders[0].uri.fsPath, '.pasteshield-policy.json');
    }
    
    // Fallback to extension storage
    return path.join(this.context.storagePath || this.context.globalStoragePath, 'pasteshield-policy.json');
  }

  /**
   * Load policy from file
   */
  private loadPolicy(): void {
    try {
      if (fs.existsSync(this.policyFilePath)) {
        const content = fs.readFileSync(this.policyFilePath, 'utf-8');
        this.currentPolicy = JSON.parse(content) as EnterprisePolicy;
        console.log('[Enterprise] Policy loaded:', this.currentPolicy?.name);
      } else {
        this.currentPolicy = this.getDefaultPolicy();
      }
    } catch (error) {
      console.error('[Enterprise] Failed to load policy:', error);
      this.currentPolicy = this.getDefaultPolicy();
    }
  }

  /**
   * Load team members from configuration
   */
  private loadTeamMembers(): void {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    const members = config.get<TeamMember[]>('teamMembers', []);
    this.teamMembers = members;
  }

  /**
   * Get default policy template
   */
  private getDefaultPolicy(): EnterprisePolicy {
    return {
      id: 'default-policy',
      name: 'Default Security Policy',
      description: 'Standard security policy for all developers',
      enabled: true,
      version: '1.0.0',
      rules: [
        {
          id: 'rule-1',
          type: 'block_pattern',
          severity: 'critical',
          patternNames: ['AWS Access Key ID', 'AWS Secret Access Key', 'GitHub PAT (classic)', 'Private Key (PEM)'],
          action: 'block',
          message: 'Critical credentials are blocked by enterprise policy.',
        },
        {
          id: 'rule-2',
          type: 'audit_logging',
          severity: 'high',
          action: 'audit',
          message: 'All high-severity detections are logged for compliance.',
        },
        {
          id: 'rule-3',
          type: 'rotation_policy',
          severity: 'medium',
          action: 'warn',
          message: 'Secrets older than 90 days should be rotated.',
        },
      ],
    };
  }

  /**
   * Check if a detection violates any policy rule
   */
  public checkPolicyViolation(
    detectionType: string,
    severity: string,
    category?: string,
    filePath?: string
  ): { violated: boolean; rule?: PolicyRule; action: string; message?: string } {
    if (!this.currentPolicy || !this.currentPolicy.enabled) {
      return { violated: false, action: 'allow' };
    }

    for (const rule of this.currentPolicy.rules) {
      // Check if file is in exceptions
      if (filePath && rule.exceptions) {
        const isException = rule.exceptions.some(exc => filePath.includes(exc));
        if (isException) {
          continue;
        }
      }

      // Check pattern-based rules
      if (rule.type === 'block_pattern' && rule.patternNames) {
        if (rule.patternNames.includes(detectionType)) {
          return {
            violated: true,
            rule,
            action: rule.action,
            message: rule.message || `Policy violation: ${rule.id}`,
          };
        }
      }

      // Check category-based rules
      if (rule.type === 'allowed_categories' && rule.categories && category) {
        if (!rule.categories.includes(category)) {
          return {
            violated: true,
            rule,
            action: rule.action,
            message: rule.message || `Category "${category}" is not allowed by policy.`,
          };
        }
      }

      // Check severity-based rules
      if (rule.severity === severity && rule.action === 'block') {
        return {
          violated: true,
          rule,
          action: 'block',
          message: rule.message || `${severity.toUpperCase()} severity is blocked by policy.`,
        };
      }
    }

    return { violated: false, action: 'allow' };
  }

  /**
   * Apply policy action based on violation result
   */
  public async applyPolicyAction(
    violation: { violated: boolean; rule?: PolicyRule; action: string; message?: string },
    detectionType: string
  ): Promise<'blocked' | 'warned' | 'allowed' | 'audited'> {
    if (!violation.violated) {
      return 'allowed';
    }

    switch (violation.action) {
      case 'block':
        vscode.window.showErrorMessage(
          `🚫 Enterprise Policy Violation\n\n${violation.message}\n\nPattern: ${detectionType}`,
          { modal: true }
        );
        return 'blocked';

      case 'warn':
        vscode.window.showWarningMessage(
          `⚠️ Policy Warning\n\n${violation.message}\n\nPattern: ${detectionType}`
        );
        return 'warned';

      case 'audit':
        console.log('[Enterprise] Audit log:', {
          timestamp: Date.now(),
          type: detectionType,
          rule: violation.rule?.id,
        });
        return 'audited';

      case 'encrypt':
        vscode.window.showInformationMessage(
          `🔐 ${detectionType} detected - encryption recommended.\n\n${violation.message}`
        );
        return 'audited';

      default:
        return 'allowed';
    }
  }

  /**
   * Create a new policy from template
   */
  public async createPolicyFromTemplate(template: 'strict' | 'moderate' | 'permissive'): Promise<void> {
    const templates: Record<string, EnterprisePolicy> = {
      strict: {
        id: 'strict-policy',
        name: 'Strict Security Policy',
        description: 'Blocks all critical and high severity patterns',
        enabled: true,
        version: '1.0.0',
        rules: [
          {
            id: 'strict-1',
            type: 'block_pattern',
            severity: 'critical',
            patternNames: [], // All critical patterns
            action: 'block',
            message: 'Critical credentials are strictly prohibited.',
          },
          {
            id: 'strict-2',
            type: 'block_pattern',
            severity: 'high',
            patternNames: [],
            action: 'block',
            message: 'High-risk credentials are blocked.',
          },
          {
            id: 'strict-3',
            type: 'audit_logging',
            severity: 'medium',
            action: 'audit',
          },
        ],
      },
      moderate: {
        id: 'moderate-policy',
        name: 'Moderate Security Policy',
        description: 'Blocks critical patterns, warns on high severity',
        enabled: true,
        version: '1.0.0',
        rules: [
          {
            id: 'mod-1',
            type: 'block_pattern',
            severity: 'critical',
            patternNames: [],
            action: 'block',
          },
          {
            id: 'mod-2',
            type: 'block_pattern',
            severity: 'high',
            patternNames: [],
            action: 'warn',
          },
        ],
      },
      permissive: {
        id: 'permissive-policy',
        name: 'Permissive Security Policy',
        description: 'Warns on all detections but allows paste',
        enabled: true,
        version: '1.0.0',
        rules: [
          {
            id: 'perm-1',
            type: 'audit_logging',
            severity: 'critical',
            action: 'audit',
          },
        ],
      },
    };

    this.currentPolicy = templates[template];
    await this.savePolicy();
    vscode.window.showInformationMessage(`Policy "${this.currentPolicy.name}" applied successfully.`);
  }

  /**
   * Save policy to file
   */
  public async savePolicy(): Promise<void> {
    if (!this.currentPolicy) return;

    try {
      // Ensure directory exists
      const dir = path.dirname(this.policyFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(this.policyFilePath, JSON.stringify(this.currentPolicy, null, 2), 'utf-8');
      vscode.window.showInformationMessage('Enterprise policy saved successfully.');
    } catch (error) {
      vscode.window.showErrorMessage(`Failed to save policy: ${(error as Error).message}`);
    }
  }

  /**
   * Generate compliance report
   */
  public generateComplianceReport(
    history: Array<{
      timestamp: number;
      fileName: string;
      detections: Array<{ type: string; severity: string; category?: string }>;
      actionTaken: string;
    }>
  ): ComplianceReport {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const filteredHistory = history.filter(h => h.timestamp >= thirtyDaysAgo.getTime());

    let policyViolations = 0;
    let blockedPastes = 0;
    let warningsIssued = 0;
    const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const typeCounts: Record<string, number> = {};
    const userViolations: Record<string, number> = {};

    for (const entry of filteredHistory) {
      for (const det of entry.detections) {
        severityCounts[det.severity] = (severityCounts[det.severity] || 0) + 1;
        typeCounts[det.type] = (typeCounts[det.type] || 0) + 1;

        const violation = this.checkPolicyViolation(det.type, det.severity, det.category, entry.fileName);
        if (violation.violated) {
          policyViolations++;
          // In real implementation, track by actual user
          userViolations['current_user'] = (userViolations['current_user'] || 0) + 1;
        }
      }

      if (entry.actionTaken === 'cancelled') {
        blockedPastes++;
      }
      if (entry.actionTaken === 'warned') {
        warningsIssued++;
      }
    }

    const topViolators = Object.entries(userViolations)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([user, violations]) => ({ user, violations }));

    const topTypes = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => ({ type, count }));

    // Calculate compliance score (0-100)
    const totalDetections = filteredHistory.reduce((sum, h) => sum + h.detections.length, 0);
    const complianceScore = totalDetections > 0
      ? Math.round(100 - (policyViolations / totalDetections) * 100)
      : 100;

    return {
      generatedAt: now.toISOString(),
      period: {
        start: thirtyDaysAgo.toISOString(),
        end: now.toISOString(),
      },
      totalScans: filteredHistory.length,
      policyViolations,
      blockedPastes,
      warningsIssued,
      criticalDetections: severityCounts.critical || 0,
      highDetections: severityCounts.high || 0,
      mediumDetections: severityCounts.medium || 0,
      lowDetections: severityCounts.low || 0,
      topViolators,
      topDetectedTypes: topTypes,
      complianceScore,
    };
  }

  /**
   * Export compliance report to JSON
   */
  public async exportComplianceReport(report: ComplianceReport): Promise<void> {
    const content = JSON.stringify(report, null, 2);
    
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(`compliance-report-${new Date().toISOString().split('T')[0]}.json`),
      filters: { JSON: ['json'] },
    });

    if (uri) {
      await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
      vscode.window.showInformationMessage(`Compliance report exported to ${uri.fsPath}`);
    }
  }

  /**
   * Get current policy
   */
  public getCurrentPolicy(): EnterprisePolicy | null {
    return this.currentPolicy;
  }

  /**
   * Enable or disable policy enforcement
   */
  public async togglePolicy(enabled: boolean): Promise<void> {
    if (!this.currentPolicy) return;
    
    this.currentPolicy.enabled = enabled;
    await this.savePolicy();
    
    vscode.window.showInformationMessage(
      `Enterprise policy ${enabled ? 'enabled' : 'disabled'}.`
    );
  }

  /**
   * Add a new rule to the policy
   */
  public async addRule(rule: PolicyRule): Promise<void> {
    if (!this.currentPolicy) return;
    
    this.currentPolicy.rules.push(rule);
    await this.savePolicy();
  }

  /**
   * Remove a rule from the policy
   */
  public async removeRule(ruleId: string): Promise<void> {
    if (!this.currentPolicy) return;
    
    this.currentPolicy.rules = this.currentPolicy.rules.filter(r => r.id !== ruleId);
    await this.savePolicy();
  }

  /**
   * Refresh policy from file
   */
  public refresh(): void {
    this.loadPolicy();
  }

  /**
   * Check if enterprise mode is enabled
   */
  public isEnterpriseModeEnabled(): boolean {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    return config.get<boolean>('enterpriseMode', false);
  }
}