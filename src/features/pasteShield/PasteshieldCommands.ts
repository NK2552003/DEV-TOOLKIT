import * as vscode from "vscode";
import { CustomPatternsManager } from "./customPatternsManager";
import { SecretManagementIntegration } from "./secretManagement";
import { EnterprisePolicyManager } from "./enterprisePolicy";

export function registerPasteShieldCommands(context: vscode.ExtensionContext): void {
  const customPatternsManager = CustomPatternsManager.getInstance(context);

  // ── Manage Custom Patterns ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("pasteShield.manageCustomPatterns", async () => {
      const patterns = customPatternsManager.getAllPatterns();

      if (patterns.length === 0) {
        const choice = await vscode.window.showInformationMessage(
          "No custom patterns defined. Would you like to add one?",
          "Add Pattern",
          "Import Patterns",
          "Cancel"
        );

        if (choice === "Add Pattern") {
          await promptAddCustomPattern(customPatternsManager);
        } else if (choice === "Import Patterns") {
          await promptImportPatterns(customPatternsManager);
        }
        return;
      }

      const selected = await vscode.window.showQuickPick(
        patterns.map((p) => ({ label: p.name, description: p.category })),
        { placeHolder: "Select a pattern to manage" }
      );

      if (!selected) return;

      const pattern = patterns.find((p) => p.name === selected.label);
      if (!pattern) return;

      const action = await vscode.window.showQuickPick(
        ["Edit", "Toggle Enable/Disable", "Remove", "Export"],
        { placeHolder: `Manage "${pattern.name}"` }
      );

      switch (action) {
        case "Edit":
          await promptEditCustomPattern(customPatternsManager, pattern);
          break;
        case "Toggle Enable/Disable":
          await customPatternsManager.togglePattern(pattern.name, !pattern.enabled);
          break;
        case "Remove":
          await customPatternsManager.removePattern(pattern.name);
          break;
        case "Export":
          await exportCustomPatterns(customPatternsManager);
          break;
      }
    })
  );

  // ── Configure Secret Manager ──────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("pasteShield.configureSecretManager", async () => {
      const provider = await vscode.window.showQuickPick(
        [
          { label: "none",  description: "No secret manager — use VS Code SecretStorage (OS keychain)" },
          { label: "vault", description: "HashiCorp Vault" },
          { label: "aws",   description: "AWS Secrets Manager" },
          { label: "azure", description: "Azure Key Vault" },
          { label: "gcp",   description: "Google Secret Manager" },
        ],
        { placeHolder: "Select secret manager provider" }
      );

      if (!provider) return;

      const config = vscode.workspace.getConfiguration("pasteShield");
      await config.update("secretManagerProvider", provider.label, vscode.ConfigurationTarget.Global);

      if (provider.label !== "none") {
        const secretManager = SecretManagementIntegration.getInstance(context);
        await promptForProviderCredentials(secretManager, provider.label);
      }

      vscode.window.showInformationMessage(
        "Secret manager configured. Credentials are stored securely via VS Code SecretStorage — never in settings.json."
      );
    })
  );

  // ── List Stored Secrets ───────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("pasteShield.listStoredSecrets", async () => {
      const secretManager = SecretManagementIntegration.getInstance(context);

      if (!secretManager.isConfigured()) {
        const choice = await vscode.window.showWarningMessage(
          "Secret manager is not configured. Configure it now?",
          "Configure",
          "Cancel"
        );
        if (choice === "Configure") {
          await vscode.commands.executeCommand("pasteShield.configureSecretManager");
        }
        return;
      }

      const secrets = await secretManager.listStoredSecrets();

      if (secrets.length === 0) {
        vscode.window.showInformationMessage("No secrets stored yet.");
        return;
      }

      const quickPickItems = secrets.map((s) => ({
        label: s.name,
        description: s.metadata.type,
        detail: `Stored: ${new Date(s.metadata.storedAt).toLocaleString()}`,
        secret: s,
      }));

      const selected = await vscode.window.showQuickPick(quickPickItems, {
        placeHolder: "Select a stored secret",
      });

      if (!selected) return;

      const action = await vscode.window.showQuickPick(
        ["View Details", "Rotate", "Delete"],
        { placeHolder: `Action for ${selected.label}` }
      );

      switch (action) {
        case "View Details":
          vscode.window.showInformationMessage(
            `Secret: ${selected.label}\nType: ${selected.description}\nDetected: ${new Date(
              selected.secret.metadata.detectedAt
            ).toLocaleString()}\nStored: ${new Date(selected.secret.metadata.storedAt).toLocaleString()}`
          );
          break;

        case "Rotate": {
          const newValue = await vscode.window.showInputBox({
            prompt: "Enter new secret value",
            password: true,
          });
          if (newValue) {
            await secretManager.rotateStoredSecret(selected.secret.id, newValue);
          }
          break;
        }

        case "Delete": {
          const confirm = await vscode.window.showWarningMessage(
            `Are you sure you want to delete ${selected.label}?`,
            { modal: true },
            "Delete"
          );
          if (confirm === "Delete") {
            await secretManager.deleteStoredSecret(selected.secret.id);
          }
          break;
        }
      }
    })
  );

  // ── Show Enterprise Policy ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("pasteShield.showEnterprisePolicy", async () => {
      const policyManager = EnterprisePolicyManager.getInstance(context);

      if (!policyManager.isEnterpriseModeEnabled()) {
        const choice = await vscode.window.showInformationMessage(
          "Enterprise mode is not enabled. Enable it now?",
          "Enable",
          "Cancel"
        );
        if (choice === "Enable") {
          const config = vscode.workspace.getConfiguration("pasteShield");
          await config.update("enterpriseMode", true, vscode.ConfigurationTarget.Global);
          vscode.window.showInformationMessage(
            "Enterprise mode enabled. Configure policies in settings."
          );
        }
        return;
      }

      const policy = policyManager.getCurrentPolicy();

      if (!policy) {
        vscode.window.showInformationMessage("No enterprise policy configured.");
        return;
      }

      const report = policyManager.generateComplianceReport([]);

      const content = `╔══════════════════════════════════════════════════════╗
║         PasteShield Enterprise Policy Report         ║
╚══════════════════════════════════════════════════════╝

Policy: ${policy.name}
Version: ${policy.version}
Status: ${policy.enabled ? "✅ Enabled" : "❌ Disabled"}
Description: ${policy.description}

┌──────────────────────────────────────────────────────┐
│                    RULES                             │
└──────────────────────────────────────────────────────┘

${policy.rules.map((r, i) => `[${i + 1}] ${r.id}: ${r.type} (${r.severity}) → ${r.action}`).join("\n")}

┌──────────────────────────────────────────────────────┐
│               COMPLIANCE SUMMARY                     │
└──────────────────────────────────────────────────────┘

Compliance Score: ${report.complianceScore}/100
Total Scans (30 days): ${report.totalScans}
Policy Violations: ${report.policyViolations}
Blocked Pastes: ${report.blockedPastes}
`;

      const doc = await vscode.workspace.openTextDocument({ content, language: "plaintext" });
      await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
    })
  );

  // ── Export Compliance Report ──────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("pasteShield.exportComplianceReport", async () => {
      const policyManager = EnterprisePolicyManager.getInstance(context);

      if (!policyManager.isEnterpriseModeEnabled()) {
        vscode.window.showWarningMessage(
          "Enterprise mode must be enabled to export compliance reports."
        );
        return;
      }

      const report = policyManager.generateComplianceReport([]);
      await policyManager.exportComplianceReport(report);
    })
  );
}

// ── Private helpers ───────────────────────────────────────────────────────────

async function promptAddCustomPattern(manager: CustomPatternsManager): Promise<void> {
  const name = await vscode.window.showInputBox({
    prompt: "Enter pattern name",
    placeHolder: "e.g., My Company API Key",
  });
  if (!name) return;

  const regex = await vscode.window.showInputBox({
    prompt: "Enter regex pattern",
    placeHolder: "e.g., MYCOMPANY_[a-zA-Z0-9]{32}",
  });
  if (!regex) return;

  const severity = await vscode.window.showQuickPick(["critical", "high", "medium", "low"], {
    placeHolder: "Select severity level",
  });
  if (!severity) return;

  const description = await vscode.window.showInputBox({
    prompt: "Enter description",
    placeHolder: "What does this pattern detect?",
  });

  const category = await vscode.window.showInputBox({
    prompt: "Enter category",
    placeHolder: "e.g., Custom, Company-Specific",
    value: "Custom",
  });

  await manager.addPattern({
    name,
    regex,
    severity: severity as "critical" | "high" | "medium" | "low",
    description: description || "",
    category: category || "Custom",
    enabled: true,
  });
}

async function promptEditCustomPattern(
  manager: CustomPatternsManager,
  pattern: import("./customPatternsManager").CustomPattern
): Promise<void> {
  const newName = await vscode.window.showInputBox({
    prompt: "Enter pattern name",
    value: pattern.name,
  });
  if (!newName) return;

  const newRegex = await vscode.window.showInputBox({
    prompt: "Enter regex pattern",
    value: pattern.regex,
  });
  if (!newRegex) return;

  const newSeverity = await vscode.window.showQuickPick(["critical", "high", "medium", "low"], {
    placeHolder: "Select severity level",
  });
  if (!newSeverity) return;

  await manager.editPattern(pattern.name, {
    ...pattern,
    name: newName,
    regex: newRegex,
    severity: newSeverity as "critical" | "high" | "medium" | "low",
  });
}

async function promptImportPatterns(manager: CustomPatternsManager): Promise<void> {
  const uri = await vscode.window.showOpenDialog({
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    filters: { JSON: ["json"] },
  });
  if (!uri || uri.length === 0) return;

  const file = await vscode.workspace.fs.readFile(uri[0]);
  await manager.importPatterns(Buffer.from(file).toString("utf8"));
}

async function exportCustomPatterns(manager: CustomPatternsManager): Promise<void> {
  const content = manager.exportPatterns();

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file("pasteshield-custom-patterns.json"),
    filters: { JSON: ["json"] },
  });

  if (uri) {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, "utf8"));
    vscode.window.showInformationMessage(`Custom patterns exported to ${uri.fsPath}`);
  }
}

async function promptForProviderCredentials(
  secretManager: SecretManagementIntegration,
  provider: string
): Promise<void> {
  const passwordInput = (prompt: string, placeHolder: string) =>
    vscode.window.showInputBox({ prompt, placeHolder, password: true });

  switch (provider) {
    case "vault": {
      const token = await passwordInput("Enter Vault authentication token", "hvs.xxx...");
      if (token) await secretManager.storeCredential("vaultToken", token);
      break;
    }
    case "aws": {
      const accessKeyId = await passwordInput("Enter AWS Access Key ID", "AKIA...");
      if (accessKeyId) await secretManager.storeCredential("awsAccessKeyId", accessKeyId);
      const secretKey = await passwordInput("Enter AWS Secret Access Key", "");
      if (secretKey) await secretManager.storeCredential("awsSecretAccessKey", secretKey);
      break;
    }
    case "azure": {
      const tenantId = await passwordInput("Enter Azure AD Tenant ID", "00000000-0000-0000-0000-000000000000");
      if (tenantId) await secretManager.storeCredential("azureTenantId", tenantId);
      const clientId = await passwordInput("Enter Azure Client ID", "");
      if (clientId) await secretManager.storeCredential("azureClientId", clientId);
      const clientSecret = await passwordInput("Enter Azure Client Secret", "");
      if (clientSecret) await secretManager.storeCredential("azureClientSecret", clientSecret);
      break;
    }
    case "gcp": {
      const credentials = await passwordInput(
        "Enter GCP service account credentials (JSON)",
        '{ "type": "service_account", ... }'
      );
      if (credentials) await secretManager.storeCredential("gcpCredentials", credentials);
      break;
    }
  }
}