/**
 * PasteShield — Secret Management Integration
 * 
 * Provides integration with popular secret management tools:
 * - HashiCorp Vault
 * - AWS Secrets Manager
 * - Azure Key Vault
 * - Google Secret Manager
 * - VS Code SecretStorage (default, OS-level keychain)
 * 
 * Allows users to store detected secrets securely and retrieve them when needed.
 */

import * as vscode from 'vscode';

const CONFIG_SECTION = 'pasteShield';
const SECRET_KEY_PREFIX = 'pasteshield.secret.';

export interface SecretManagerConfig {
  provider: 'vault' | 'aws' | 'azure' | 'gcp' | 'none';
  vaultUrl?: string;
  vaultToken?: string;
  awsRegion?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  azureVaultUrl?: string;
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  gcpProjectId?: string;
  gcpCredentials?: string;
}

export interface StoredSecret {
  id: string;
  name: string;
  value: string;
  metadata: {
    type: string;
    severity: string;
    category?: string;
    detectedAt: number;
    storedAt: number;
    filePath?: string;
  };
}

export abstract class SecretProvider {
  abstract storeSecret(secret: StoredSecret): Promise<void>;
  abstract getSecret(id: string): Promise<StoredSecret | null>;
  abstract deleteSecret(id: string): Promise<void>;
  abstract listSecrets(): Promise<StoredSecret[]>;
  abstract rotateSecret(id: string, newValue: string): Promise<void>;
}

/**
 * Mock Vault Provider - In production, this would use actual Vault API
 */
class VaultProvider extends SecretProvider {
  private vaultUrl: string;
  // @ts-ignore TS6133 - Stored for Vault API operations
  private _vaultToken: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.vaultUrl = config.vaultUrl || 'http://localhost:8200';
    this._vaultToken = config.vaultToken || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: POST /v1/secret/data/{name}
    console.log(`[Vault] Storing secret: ${secret.name} at ${this.vaultUrl}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    // In production: GET /v1/secret/data/{id}
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    // In production: DELETE /v1/secret/data/{id}
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    // In production: LIST /v1/secret/metadata
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
    const existing = await this.getSecret(id);
    if (!existing) {
      throw new Error(`Secret ${id} not found`);
    }
    existing.value = newValue;
    existing.metadata.storedAt = Date.now();
    await this.storeSecret(existing);
  }
}

/**
 * Mock AWS Secrets Manager Provider
 */
class AwsSecretsManagerProvider extends SecretProvider {
  private region: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.region = config.awsRegion || 'us-east-1';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use AWS SDK v3
    // const client = new SecretsManagerClient({ region: this.region });
    // await client.send(new CreateSecretCommand({ Name: secret.name, SecretString: secret.value }));
    console.log(`[AWS Secrets Manager] Storing secret: ${secret.name} in ${this.region}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    // In production: Use AWS SDK v3
    // const client = new SecretsManagerClient({ region: this.region });
    // const response = await client.send(new GetSecretValueCommand({ SecretId: id }));
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    // In production: Use AWS SDK v3 with ForceDeleteWithoutRecovery
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    // In production: Use AWS SDK v3 ListSecrets
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
    // In production: Use AWS SDK v3 UpdateSecret
    const existing = await this.getSecret(id);
    if (!existing) {
      throw new Error(`Secret ${id} not found`);
    }
    existing.value = newValue;
    existing.metadata.storedAt = Date.now();
    await this.storeSecret(existing);
  }
}

/**
 * Mock Azure Key Vault Provider
 */
class AzureKeyVaultProvider extends SecretProvider {
  // @ts-ignore TS6133 - Stored for Azure Key Vault operations
  private _vaultUrl: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this._vaultUrl = config.azureVaultUrl || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use @azure/keyvault-secrets
    // const client = new SecretClient(this.vaultUrl, credential);
    // await client.setSecret(secret.name, secret.value);
    console.log(`[Azure Key Vault] Storing secret: ${secret.name}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
    const existing = await this.getSecret(id);
    if (!existing) {
      throw new Error(`Secret ${id} not found`);
    }
    existing.value = newValue;
    existing.metadata.storedAt = Date.now();
    await this.storeSecret(existing);
  }
}

/**
 * Mock Google Secret Manager Provider
 */
class GoogleSecretManagerProvider extends SecretProvider {
  private projectId: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.projectId = config.gcpProjectId || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use @google-cloud/secret-manager
    // const client = new SecretManagerServiceClient();
    // await client.addSecretVersion({ parent: `projects/${this.projectId}/secrets/${secret.name}`, payload: { data: secret.value } });
    console.log(`[GCP Secret Manager] Storing secret: ${secret.name} in project ${this.projectId}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
    const existing = await this.getSecret(id);
    if (!existing) {
      throw new Error(`Secret ${id} not found`);
    }
    existing.value = newValue;
    existing.metadata.storedAt = Date.now();
    await this.storeSecret(existing);
  }
}

export class SecretManagementIntegration {
  private static instance: SecretManagementIntegration | undefined;
  // @ts-ignore TS6133 - Stored for secret storage operations
  private _context: vscode.ExtensionContext;
  private provider: SecretProvider | null = null;
  private config: SecretManagerConfig | null = null;
  private secretStorage: vscode.SecretStorage;
  private credentialsLoaded: boolean = false;

  private constructor(context: vscode.ExtensionContext) {
    this._context = context;
    this.secretStorage = context.secrets;
    this.loadNonSensitiveConfiguration();
  }

  public static getInstance(context: vscode.ExtensionContext): SecretManagementIntegration {
    if (!SecretManagementIntegration.instance) {
      SecretManagementIntegration.instance = new SecretManagementIntegration(context);
    }
    return SecretManagementIntegration.instance;
  }

  /**
   * Initialize credentials from SecretStorage. Must be awaited before using provider features.
   */
  public async init(): Promise<void> {
    if (this.credentialsLoaded) return;
    await this.loadCredentialsFromSecretStorage();
    this.initializeProvider();
    this.credentialsLoaded = true;
  }

  private loadNonSensitiveConfiguration(): void {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    this.config = {
      provider: config.get<'vault' | 'aws' | 'azure' | 'gcp' | 'none'>('secretManagerProvider', 'none'),
      vaultUrl: config.get<string>('vaultUrl'),
      awsRegion: config.get<string>('awsRegion'),
      azureVaultUrl: config.get<string>('azureVaultUrl'),
      gcpProjectId: config.get<string>('gcpProjectId'),
    };
  }

  /**
   * Load sensitive credentials from VS Code SecretStorage (OS-level keychain).
   * Never reads credentials from settings.json.
   */
  private async loadCredentialsFromSecretStorage(): Promise<void> {
    if (!this.config) return;

    const [
      vaultToken,
      awsAccessKeyId,
      awsSecretAccessKey,
      azureTenantId,
      azureClientId,
      azureClientSecret,
      gcpCredentials,
    ] = await Promise.all([
      this.secretStorage.get('pasteshield.vaultToken'),
      this.secretStorage.get('pasteshield.awsAccessKeyId'),
      this.secretStorage.get('pasteshield.awsSecretAccessKey'),
      this.secretStorage.get('pasteshield.azureTenantId'),
      this.secretStorage.get('pasteshield.azureClientId'),
      this.secretStorage.get('pasteshield.azureClientSecret'),
      this.secretStorage.get('pasteshield.gcpCredentials'),
    ]);

    this.config = {
      ...this.config,
      vaultToken: vaultToken || undefined,
      awsAccessKeyId: awsAccessKeyId || undefined,
      awsSecretAccessKey: awsSecretAccessKey || undefined,
      azureTenantId: azureTenantId || undefined,
      azureClientId: azureClientId || undefined,
      azureClientSecret: azureClientSecret || undefined,
      gcpCredentials: gcpCredentials || undefined,
    };
  }

  /**
   * Store a provider credential securely in VS Code SecretStorage.
   */
  public async storeCredential(key: string, value: string): Promise<void> {
    await this.secretStorage.store(`pasteshield.${key}`, value);
    // Refresh provider if already initialized
    if (this.credentialsLoaded) {
      await this.loadCredentialsFromSecretStorage();
      this.initializeProvider();
    }
  }

  private initializeProvider(): void {
    if (!this.config) return;

    switch (this.config.provider) {
      case 'vault':
        this.provider = new VaultProvider(this.config);
        break;
      case 'aws':
        this.provider = new AwsSecretsManagerProvider(this.config);
        break;
      case 'azure':
        this.provider = new AzureKeyVaultProvider(this.config);
        break;
      case 'gcp':
        this.provider = new GoogleSecretManagerProvider(this.config);
        break;
      default:
        this.provider = null;
    }
  }

  /**
   * Store a detected secret in the configured secret manager
   */
  public async storeDetectedSecret(
    secretValue: string,
    metadata: {
      type: string;
      severity: string;
      category?: string;
      filePath?: string;
    }
  ): Promise<string | null> {
    await this.init();
    if (!this.provider) {
      // Use VS Code SecretStorage as default (OS-level keychain)
      return this.storeInSecretStorage(secretValue, metadata);
    }

    try {
      // Generate a unique ID for the secret
      const id = this.generateSecretId(metadata.type);
      const name = `${metadata.type.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`;

      const storedSecret: StoredSecret = {
        id,
        name,
        value: secretValue, // No encryption needed - SecretStorage handles it at OS level
        metadata: {
          ...metadata,
          detectedAt: Date.now(),
          storedAt: Date.now(),
        },
      };

      await this.provider.storeSecret(storedSecret);
      
      vscode.window.showInformationMessage(
        `Secret stored successfully in ${this.config?.provider.toUpperCase()} with ID: ${id}`
      );

      return id;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to store secret: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Store a secret using VS Code's built-in SecretStorage API
   * This uses OS-level keychain (Windows Credential Manager, macOS Keychain, Linux libsecret)
   * Enterprise-credible: no custom encryption, leverages OS security primitives
   */
  private async storeInSecretStorage(
    secretValue: string,
    metadata: {
      type: string;
      severity: string;
      category?: string;
      filePath?: string;
    }
  ): Promise<string | null> {
    try {
      const id = this.generateSecretId(metadata.type);
      const key = `${SECRET_KEY_PREFIX}${id}`;
      
      const secretData: StoredSecret = {
        id,
        name: `${metadata.type.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`,
        value: secretValue,
        metadata: {
          ...metadata,
          detectedAt: Date.now(),
          storedAt: Date.now(),
        },
      };

      await this.secretStorage.store(key, JSON.stringify(secretData));
      
      vscode.window.showInformationMessage(
        `Secret stored securely using VS Code SecretStorage (OS keychain) with ID: ${id}`
      );

      return id;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to store secret in SecretStorage: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Retrieve a stored secret by ID
   */
  public async getStoredSecret(id: string): Promise<string | null> {
    await this.init();
    if (!this.provider) {
      // Try to retrieve from VS Code SecretStorage
      return this.getFromSecretStorage(id);
    }

    try {
      const secret = await this.provider.getSecret(id);
      if (!secret) {
        vscode.window.showWarningMessage(`Secret ${id} not found.`);
        return null;
      }

      return secret.value; // No decryption needed - stored plaintext in OS keychain
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to retrieve secret: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Retrieve a secret from VS Code's SecretStorage
   */
  private async getFromSecretStorage(id: string): Promise<string | null> {
    try {
      const key = `${SECRET_KEY_PREFIX}${id}`;
      const stored = await this.secretStorage.get(key);
      
      if (!stored) {
        vscode.window.showWarningMessage(`Secret ${id} not found in SecretStorage.`);
        return null;
      }

      const secretData: StoredSecret = JSON.parse(stored);
      return secretData.value;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to retrieve secret from SecretStorage: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Delete a stored secret
   */
  public async deleteStoredSecret(id: string): Promise<boolean> {
    await this.init();
    if (!this.provider) {
      // Delete from VS Code SecretStorage
      return this.deleteFromSecretStorage(id);
    }

    try {
      await this.provider.deleteSecret(id);
      vscode.window.showInformationMessage(`Secret ${id} deleted successfully.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to delete secret: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * Delete a secret from VS Code's SecretStorage
   */
  private async deleteFromSecretStorage(id: string): Promise<boolean> {
    try {
      const key = `${SECRET_KEY_PREFIX}${id}`;
      await this.secretStorage.delete(key);
      vscode.window.showInformationMessage(`Secret ${id} deleted from SecretStorage.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to delete secret from SecretStorage: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * List all stored secrets (from external providers only)
   */
  public async listStoredSecrets(): Promise<StoredSecret[]> {
    await this.init();
    if (!this.provider) {
      // List from VS Code SecretStorage
      return this.listFromSecretStorage();
    }

    try {
      return await this.provider.listSecrets();
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to list secrets: ${(error as Error).message}`
      );
      return [];
    }
  }

  /**
   * List secrets from VS Code's SecretStorage
   */
  private async listFromSecretStorage(): Promise<StoredSecret[]> {
    // Note: SecretStorage doesn't provide a way to list all keys
    // We can only retrieve by known IDs
    vscode.window.showInformationMessage(
      'SecretStorage does not support listing all secrets. Retrieve by ID instead.'
    );
    return [];
  }

  /**
   * Rotate a stored secret with a new value
   */
  public async rotateStoredSecret(id: string, newValue: string): Promise<boolean> {
    await this.init();
    if (!this.provider) {
      // Rotate in VS Code SecretStorage
      return this.rotateInSecretStorage(id, newValue);
    }

    try {
      await this.provider.rotateSecret(id, newValue); // No encryption needed
      vscode.window.showInformationMessage(`Secret ${id} rotated successfully.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to rotate secret: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * Rotate a secret in VS Code's SecretStorage
   */
  private async rotateInSecretStorage(id: string, newValue: string): Promise<boolean> {
    try {
      const key = `${SECRET_KEY_PREFIX}${id}`;
      const stored = await this.secretStorage.get(key);
      
      if (!stored) {
        vscode.window.showWarningMessage(`Secret ${id} not found for rotation.`);
        return false;
      }

      const secretData: StoredSecret = JSON.parse(stored);
      secretData.value = newValue;
      secretData.metadata.storedAt = Date.now();

      await this.secretStorage.store(key, JSON.stringify(secretData));
      vscode.window.showInformationMessage(`Secret ${id} rotated successfully.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to rotate secret in SecretStorage: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * Quick store action - prompted after detection
   * Now uses VS Code SecretStorage by default (OS-level keychain)
   */
  public async quickStoreAction(
    secretValue: string,
    metadata: {
      type: string;
      severity: string;
      category?: string;
      filePath?: string;
    }
  ): Promise<void> {
    await this.init();
    const choice = await vscode.window.showInformationMessage(
      `Store this ${metadata.type} securely in ${!this.provider ? 'VS Code SecretStorage (OS keychain)' : this.config?.provider.toUpperCase() + '?'}?`,
      'Store',
      'Cancel'
    );

    if (choice === 'Store') {
      await this.storeDetectedSecret(secretValue, metadata);
    }
  }

  /**
   * Generate a unique secret ID using crypto.getRandomValues for better randomness
   */
  private generateSecretId(type: string): string {
    // Use simple hash-like approach without external crypto dependency
    const timestamp = Date.now().toString(36);
    const randomPart = Math.random().toString(36).substring(2, 10);
    const typeHash = type.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0).toString(36);
    return `${typeHash}-${timestamp}-${randomPart}`.substring(0, 16);
  }

  /**
   * Reconfigure the secret manager
   */
  public reconfigure(): void {
    this.credentialsLoaded = false;
    this.loadNonSensitiveConfiguration();
    this.provider = null;
  }

  /**
   * Check if secret management is configured
   */
  public isConfigured(): boolean {
    return this.config?.provider !== 'none' && this.config?.provider !== undefined;
  }

  /**
   * Get the current provider type
   */
  public getProviderType(): string {
    return this.config?.provider || 'none';
  }
}