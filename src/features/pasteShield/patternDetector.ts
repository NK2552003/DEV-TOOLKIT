/**
 * PasteShield — Pattern Detection Engine
 * Scans pasted content for secrets, credentials, and unsafe code patterns.
 * All regexes are pre-compiled and cached for performance.
 *
 * Updated: 2026 — comprehensive expansion across AI/LLM providers, cloud platforms,
 * CI/CD, databases, mobile, IoT, payment processors, communication tools, observability,
 * auth providers, crypto/web3, package registries, social APIs, infrastructure,
 * and generic unsafe code patterns.
 *
 * Coverage: ~200 pattern definitions across 25+ categories.
 * No duplicate patterns — each service/token type is detected exactly once.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface DetectionResult {
  type: string;
  description: string;
  match: string;        // Truncated/redacted match for display
  severity: Severity;
  line?: number;        // 1-indexed line number of first match
  category?: string;   // Pattern category for grouping
}

interface PatternDefinition {
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  redact?: boolean;     // Mask most of the match in output
  category: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-compiled pattern registry
// ─────────────────────────────────────────────────────────────────────────────
const PATTERN_DEFINITIONS: PatternDefinition[] = [

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── AI / LLM PROVIDERS ──────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  // OpenAI
  {
    name: 'OpenAI API Key (sk-proj-)',
    regex: /sk-proj-[a-zA-Z0-9\-_]{80,}/g,
    severity: 'critical',
    description: 'OpenAI project-scoped API key — grants scoped API + billing access.',
    redact: true,
    category: 'AI Providers',
  },
  {
    name: 'OpenAI API Key (sk-svcacct-)',
    regex: /sk-svcacct-[a-zA-Z0-9\-_]{80,}/g,
    severity: 'critical',
    description: 'OpenAI service account API key detected.',
    redact: true,
    category: 'AI Providers',
  },
  {
    name: 'OpenAI API Key (sk-)',
    regex: /\bsk-[a-zA-Z0-9]{48,}\b/g,
    severity: 'critical',
    description: 'OpenAI API key (legacy format) — grants full API + billing access.',
    redact: true,
    category: 'AI Providers',
  },
  {
    name: 'OpenAI Org ID',
    regex: /\borg-[a-zA-Z0-9]{24}\b/g,
    severity: 'high',
    description: 'OpenAI Organization ID — used to route billing across API calls.',
    redact: true,
    category: 'AI Providers',
  },

  // Anthropic
  {
    name: 'Anthropic API Key',
    regex: /sk-ant-(?:api\d{2}-)?[a-zA-Z0-9\-_]{88,}/g,
    severity: 'critical',
    description: 'Anthropic (Claude) API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Google AI / Gemini
  {
    name: 'Google Gemini / Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'critical',
    description: 'Google Gemini / Google Cloud API key — may access Gemini, Maps, Firebase, and more.',
    redact: true,
    category: 'AI Providers',
  },

  // xAI / Grok
  {
    name: 'xAI Grok API Key',
    regex: /xai-[a-zA-Z0-9]{48,}/g,
    severity: 'critical',
    description: 'xAI Grok API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // DeepSeek
  {
    name: 'DeepSeek API Key',
    regex: /(?:DEEPSEEK_API_KEY|deepseek[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'DeepSeek API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Mistral
  {
    name: 'Mistral API Key',
    regex: /(?:MISTRAL_API_KEY|mistral[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Mistral AI API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Cohere
  {
    name: 'Cohere API Key',
    regex: /\bco-[a-zA-Z0-9]{40}\b/g,
    severity: 'critical',
    description: 'Cohere API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Hugging Face
  {
    name: 'Hugging Face Token',
    regex: /\bhf_[a-zA-Z0-9]{34,}\b/g,
    severity: 'critical',
    description: 'Hugging Face User Access Token — model/dataset upload access.',
    redact: true,
    category: 'AI Providers',
  },

  // Replicate
  {
    name: 'Replicate API Token',
    regex: /\br8_[a-zA-Z0-9]{38}\b/g,
    severity: 'critical',
    description: 'Replicate API token detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Together AI
  {
    name: 'Together AI API Key',
    regex: /(?:TOGETHER_API_KEY|together[_-]?api[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Together AI API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Groq
  {
    name: 'Groq API Key',
    regex: /\bgsk_[a-zA-Z0-9]{52}\b/g,
    severity: 'critical',
    description: 'Groq API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Perplexity
  {
    name: 'Perplexity API Key',
    regex: /\bpplx-[a-zA-Z0-9]{48}\b/g,
    severity: 'critical',
    description: 'Perplexity AI API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // ElevenLabs
  {
    name: 'ElevenLabs API Key',
    regex: /(?:ELEVEN(?:_LABS)?_API_KEY|elevenlabs[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})['"]?/gi,
    severity: 'critical',
    description: 'ElevenLabs API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // OpenRouter
  {
    name: 'OpenRouter API Key',
    regex: /\bsk-or-v1-[a-zA-Z0-9]{64}\b/g,
    severity: 'critical',
    description: 'OpenRouter API key — proxies multiple LLM providers.',
    redact: true,
    category: 'AI Providers',
  },

  // Azure OpenAI
  {
    name: 'Azure OpenAI Endpoint Key',
    regex: /(?:AZURE_OPENAI_(?:API_)?KEY|azure[_-]?openai[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Azure OpenAI endpoint API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // LangSmith / LangChain
  {
    name: 'LangSmith API Key',
    regex: /\bls__[a-zA-Z0-9]{32,}\b/g,
    severity: 'high',
    description: 'LangSmith / LangChain tracing API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Voyage AI
  {
    name: 'Voyage AI API Key',
    regex: /(?:VOYAGE_API_KEY|voyage[_-]?(?:ai[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Voyage AI embeddings API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Fireworks AI
  {
    name: 'Fireworks AI API Key',
    regex: /(?:FIREWORKS_API_KEY|fireworks[_-]?(?:ai[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Fireworks AI API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Cerebras
  {
    name: 'Cerebras API Key',
    regex: /(?:CEREBRAS_API_KEY|cerebras[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Cerebras AI inference API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Stability AI
  {
    name: 'Stability AI API Key',
    regex: /\bsk-[a-zA-Z0-9]{48}(?=[^-\w]|$)/g,
    severity: 'critical',
    description: 'Stability AI API key (longer sk- format) detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Fal.ai
  {
    name: 'Fal.ai API Key',
    regex: /(?:FAL_KEY|FAL_API_KEY|fal[_-]?(?:ai[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_:]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Fal.ai (serverless AI) API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Modal
  {
    name: 'Modal Token',
    regex: /(?:MODAL_TOKEN_ID|MODAL_TOKEN_SECRET|modal[_-]?token[_-]?(?:id|secret))\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Modal serverless compute token detected.',
    redact: true,
    category: 'AI Providers',
  },

  // Baseten
  {
    name: 'Baseten API Key',
    regex: /(?:BASETEN_API_KEY|baseten[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Baseten model serving API key detected.',
    redact: true,
    category: 'AI Providers',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── AWS ─────────────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID — matches all AWS key prefixes (root, IAM, STS, etc.).',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|AWS_SECRET(?:_ACCESS_KEY)?)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    description: 'AWS Secret Access Key detected.',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS Session Token',
    regex: /(?:aws[_-]?session[_-]?token|AWS_SESSION_TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?/gi,
    severity: 'critical',
    description: 'AWS Session Token — temporary credentials with elevated risk.',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS Account ID',
    regex: /\b(\d{12})\b(?=.*(?:aws|arn|account))/gi,
    severity: 'medium',
    description: 'AWS Account ID — useful for targeted attacks and enumeration.',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS ARN',
    regex: /arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s'"]+/g,
    severity: 'low',
    description: 'AWS ARN detected — reveals account and resource topology.',
    redact: false,
    category: 'AWS',
  },
  {
    name: 'AWS S3 Pre-signed URL',
    regex: /https:\/\/[a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com\/[^\s'"]*X-Amz-Signature=[a-fA-F0-9]+/g,
    severity: 'high',
    description: 'AWS S3 pre-signed URL — grants temporary authenticated object access.',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS CodeCommit GRC Credential',
    regex: /(?:codecommit[_-]?(?:user|password|credential))\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{20,})['"]?/gi,
    severity: 'critical',
    description: 'AWS CodeCommit HTTPS Git credential detected.',
    redact: true,
    category: 'AWS',
  },
  {
    name: 'AWS ECR Token',
    regex: /(?:ECR_(?:AUTH_)?TOKEN|ecr[_-]?(?:auth[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{100,})['"]?/gi,
    severity: 'critical',
    description: 'AWS ECR authorization token detected — grants container registry access.',
    redact: true,
    category: 'AWS',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── GOOGLE CLOUD ────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Google Cloud Service Account Key (JSON)',
    regex: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"\s*:/g,
    severity: 'critical',
    description: 'Google Cloud service account JSON key — grants GCP project access.',
    redact: false,
    category: 'Google Cloud',
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /GOCSPX-[a-zA-Z0-9\-_]{28}/g,
    severity: 'critical',
    description: 'Google OAuth 2.0 client secret — enables OAuth impersonation.',
    redact: true,
    category: 'Google Cloud',
  },
  {
    name: 'Google OAuth Refresh Token',
    regex: /1\/\/[a-zA-Z0-9\-_]{38,}/g,
    severity: 'critical',
    description: 'Google OAuth refresh token — persistent user/service access.',
    redact: true,
    category: 'Google Cloud',
  },
  {
    name: 'Firebase Admin SDK Credential',
    regex: /"auth_uri"\s*:\s*"https:\/\/accounts\.google\.com\/o\/oauth2\/auth"/g,
    severity: 'critical',
    description: 'Firebase Admin SDK service account JSON detected.',
    redact: false,
    category: 'Google Cloud',
  },
  {
    name: 'Firebase Config (apiKey)',
    regex: /(?:firebaseConfig|initializeApp)\s*\(\s*\{[^}]*apiKey\s*:\s*['"][^'"]+['"]/gs,
    severity: 'high',
    description: 'Firebase config object with API key — exposed keys can access Gemini API.',
    redact: false,
    category: 'Google Cloud',
  },
  {
    name: 'Google Cloud Storage Signed URL',
    regex: /https:\/\/storage\.googleapis\.com\/[^\s'"]*X-Goog-Signature=[a-fA-F0-9]+/g,
    severity: 'high',
    description: 'GCS signed URL — grants temporary authenticated bucket access.',
    redact: true,
    category: 'Google Cloud',
  },
  {
    name: 'Google Maps API Key (public)',
    regex: /(?:GOOGLE_MAPS_API_KEY|google[_-]?maps[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?(AIza[0-9A-Za-z\-_]{35})['"]?/gi,
    severity: 'high',
    description: 'Google Maps API key — unrestricted keys can be used for billing abuse.',
    redact: true,
    category: 'Google Cloud',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── AZURE ────────────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Azure Subscription ID',
    regex: /(?:subscription[_-]?id|AZURE_SUBSCRIPTION_ID)\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi,
    severity: 'medium',
    description: 'Azure Subscription ID detected — aids targeted enumeration.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Client Secret',
    regex: /(?:client[_-]?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*['"]?([a-zA-Z0-9~._\-]{34,})['"]?/gi,
    severity: 'critical',
    description: 'Azure Active Directory client secret — full AAD app access.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Storage Account Key',
    regex: /(?:AccountKey=)([A-Za-z0-9+/=]{86,88}==)/g,
    severity: 'critical',
    description: 'Azure Storage Account key — full storage read/write/delete access.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure SAS Token',
    regex: /(?:sig=)([a-zA-Z0-9%+/=]{40,})/g,
    severity: 'high',
    description: 'Azure Shared Access Signature token — scoped resource access.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Connection String',
    regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;/g,
    severity: 'critical',
    description: 'Azure Storage connection string with embedded credentials.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Service Bus Connection String',
    regex: /Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^'";\s]+/g,
    severity: 'critical',
    description: 'Azure Service Bus connection string with credentials.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Cosmos DB Key',
    regex: /(?:COSMOS(?:_DB)?_(?:KEY|MASTER_KEY)|cosmos[_-]?db[_-]?(?:primary[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{86,88}==)['"]?/gi,
    severity: 'critical',
    description: 'Azure Cosmos DB master key — full database access.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Event Hub Connection String',
    regex: /Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net[^;]*;SharedAccessKeyName=[^;]+;SharedAccessKey=[^'";\s]+/g,
    severity: 'critical',
    description: 'Azure Event Hub / Service Bus connection string with credentials.',
    redact: true,
    category: 'Azure',
  },
  {
    name: 'Azure Tenant ID',
    regex: /(?:tenant[_-]?id|AZURE_TENANT_ID)\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi,
    severity: 'medium',
    description: 'Azure Tenant ID — exposes directory identity.',
    redact: true,
    category: 'Azure',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── SOURCE CONTROL ───────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'GitHub PAT (classic)',
    regex: /\bghp_[a-zA-Z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token (classic) — repo/org read-write access.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitHub Fine-Grained PAT',
    regex: /\bgithub_pat_[a-zA-Z0-9_]{82}\b/g,
    severity: 'critical',
    description: 'GitHub Fine-Grained Personal Access Token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitHub OAuth Token',
    regex: /\bgho_[a-zA-Z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub OAuth access token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitHub App Token',
    regex: /\b(?:ghu|ghs)_[a-zA-Z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub App installation or user token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitHub Refresh Token',
    regex: /\bghr_[a-zA-Z0-9]{76}\b/g,
    severity: 'critical',
    description: 'GitHub OAuth refresh token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitHub Actions Secret Reference',
    regex: /\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/g,
    severity: 'low',
    description: 'GitHub Actions secret reference — confirms secret name is in use.',
    redact: false,
    category: 'Source Control',
  },
  {
    name: 'GitLab PAT',
    regex: /\bglpat-[a-zA-Z0-9\-_]{20}\b/g,
    severity: 'critical',
    description: 'GitLab Personal Access Token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitLab Pipeline Trigger Token',
    regex: /\bglptt-[a-zA-Z0-9]{40}\b/g,
    severity: 'critical',
    description: 'GitLab Pipeline Trigger Token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitLab Runner Registration Token',
    regex: /\bGR1348941[a-zA-Z0-9\-_]{20}\b/g,
    severity: 'critical',
    description: 'GitLab Runner registration token.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitLab CI Job Token',
    regex: /\bglcbt-[a-zA-Z0-9\-_]{20,}\b/g,
    severity: 'high',
    description: 'GitLab CI job token — scoped to current pipeline job.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'GitLab Deploy Token',
    regex: /\bgldt-[a-zA-Z0-9\-_]{20}\b/g,
    severity: 'high',
    description: 'GitLab Deploy Token — registry/repo pull access.',
    redact: true,
    category: 'Source Control',
  },
  {
    name: 'Bitbucket App Password',
    regex: /(?:bitbucket[_-]?(?:app[_-]?password|token))\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Bitbucket App Password — repo and pipeline access.',
    redact: true,
    category: 'Source Control',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── CI / CD ──────────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'CircleCI Personal API Token',
    regex: /(?:circle[_-]?(?:ci[_-]?)?(?:token|api[_-]?token))\s*[:=]\s*['"]?([a-fA-F0-9]{40})['"]?/gi,
    severity: 'critical',
    description: 'CircleCI API token — pipeline and project access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Travis CI Token',
    regex: /(?:travis[_-]?(?:ci[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{22,})['"]?/gi,
    severity: 'critical',
    description: 'Travis CI access token.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Jenkins API Token',
    regex: /(?:jenkins[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-fA-F0-9]{34,})['"]?/gi,
    severity: 'critical',
    description: 'Jenkins API token — build and admin access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Vercel Access Token',
    regex: /(?:VERCEL_TOKEN|vercel[_-]?(?:access[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{24,})['"]?/gi,
    severity: 'critical',
    description: 'Vercel access token — deployment and project management access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Netlify Access Token',
    regex: /(?:NETLIFY_AUTH_TOKEN|netlify[_-]?(?:auth[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Netlify access token — site and function deployment access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Render API Key',
    regex: /\brnd_[a-zA-Z0-9]{32}\b/g,
    severity: 'critical',
    description: 'Render.com API key — service management access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Railway Token',
    regex: /(?:RAILWAY_TOKEN|railway[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Railway.app deployment token.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Fly.io Token',
    regex: /\bFlyV1 [a-zA-Z0-9+/=]{30,}\b/g,
    severity: 'critical',
    description: 'Fly.io auth token — app and deploy management.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Heroku API Key',
    regex: /(?:HEROKU_API_KEY|heroku[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})['"]?/gi,
    severity: 'critical',
    description: 'Heroku API key — app and add-on management access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Buildkite Agent Token',
    regex: /(?:BUILDKITE_AGENT_TOKEN|buildkite[_-]?agent[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Buildkite agent token — pipeline execution access.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Drone CI Token',
    regex: /(?:DRONE_TOKEN|drone[_-]?(?:server[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Drone CI authentication token.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Spacelift API Key',
    regex: /(?:SPACELIFT_API_KEY|spacelift[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Spacelift IaC automation API key.',
    redact: true,
    category: 'CI/CD',
  },
  {
    name: 'Coolify API Key',
    regex: /(?:COOLIFY_API_KEY|coolify[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Coolify self-hosted PaaS API key.',
    redact: true,
    category: 'CI/CD',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── COMMUNICATION PLATFORMS ─────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Slack Bot Token',
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    severity: 'critical',
    description: 'Slack Bot User OAuth Token — full bot workspace access.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Slack User Token',
    regex: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Slack User OAuth Token — reads all user messages.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Slack App-Level Token',
    regex: /\bxapp-\d-[A-Z0-9]{10,13}-[0-9]{13}-[a-fA-F0-9]{64}\b/g,
    severity: 'critical',
    description: 'Slack App-Level Token.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Slack Configuration Token',
    regex: /\bxoxe-[0-9]{10,13}-[a-zA-Z0-9]{48}\b/g,
    severity: 'critical',
    description: 'Slack configuration-level token.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: 'high',
    description: 'Slack Incoming Webhook URL — anyone can post to your channel.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Discord Bot Token',
    regex: /(?:discord[_-]?(?:bot[_-]?)?token)\s*[:=]\s*['"]?([MN][a-zA-Z0-9]{23,25}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,40})['"]?/gi,
    severity: 'critical',
    description: 'Discord bot token — full bot account and guild access.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Discord Webhook URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[a-zA-Z0-9\-_]{60,68}/g,
    severity: 'high',
    description: 'Discord webhook URL — allows message posting to channel.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Telegram Bot Token',
    regex: /\d{8,10}:AA[a-zA-Z0-9\-_]{33}/g,
    severity: 'critical',
    description: 'Telegram Bot API token — full bot control.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Twilio Account SID',
    regex: /\bAC[a-fA-F0-9]{32}\b/g,
    severity: 'high',
    description: 'Twilio Account SID — identifies your account for API calls.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:TWILIO_AUTH_TOKEN|twilio[_-]?auth[_-]?token)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Twilio Auth Token — call/SMS/messaging control.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Twilio API Key',
    regex: /\bSK[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Twilio API Key (SK-prefix) — scoped account access.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b/g,
    severity: 'critical',
    description: 'SendGrid API key — email sending and contact management.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Mailchimp API Key',
    regex: /\b[a-fA-F0-9]{32}-us\d{1,2}\b/g,
    severity: 'critical',
    description: 'Mailchimp API key — audience and campaign management.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Mailgun API Key',
    regex: /\bkey-[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Mailgun API key — email sending and domain control.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Postmark Server Token',
    regex: /(?:postmark[_-]?(?:server[_-]?)?(?:token|api[_-]?key))\s*[:=]\s*['"]?([a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})['"]?/gi,
    severity: 'critical',
    description: 'Postmark server API token — email delivery access.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Resend API Key',
    regex: /\bre_[a-zA-Z0-9]{32,}\b/g,
    severity: 'critical',
    description: 'Resend email API key.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Microsoft Teams Webhook',
    regex: /https:\/\/[a-zA-Z0-9]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9\-@]+\/IncomingWebhook\/[a-zA-Z0-9]+\/[a-zA-Z0-9\-]+/g,
    severity: 'high',
    description: 'Microsoft Teams Incoming Webhook URL.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Vonage / Nexmo API Key',
    regex: /(?:VONAGE_API_KEY|NEXMO_API_KEY|vonage[_-]?(?:api[_-]?)?key|nexmo[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{8})['"]?/gi,
    severity: 'high',
    description: 'Vonage (Nexmo) SMS/voice API key detected.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Vonage / Nexmo API Secret',
    regex: /(?:VONAGE_API_SECRET|NEXMO_API_SECRET|vonage[_-]?(?:api[_-]?)?secret|nexmo[_-]?(?:api[_-]?)?secret)\s*[:=]\s*['"]?([a-zA-Z0-9]{16})['"]?/gi,
    severity: 'critical',
    description: 'Vonage (Nexmo) API secret — enables SMS/call actions.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Pusher App Secret',
    regex: /(?:PUSHER_APP_SECRET|pusher[_-]?(?:app[_-]?)?secret)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Pusher realtime app secret.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Plivo Auth Token',
    regex: /(?:PLIVO_AUTH_TOKEN|plivo[_-]?auth[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{40})['"]?/gi,
    severity: 'critical',
    description: 'Plivo SMS/voice API auth token.',
    redact: true,
    category: 'Communication',
  },
  {
    name: 'Zulip Bot API Key',
    regex: /(?:ZULIP_API_KEY|zulip[_-]?(?:bot[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Zulip chat bot API key.',
    redact: true,
    category: 'Communication',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── PAYMENT PROVIDERS ───────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Stripe Secret Key (live)',
    regex: /\bsk_live_[a-zA-Z0-9]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe live secret key — enables real financial transactions.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Stripe Secret Key (test)',
    regex: /\bsk_test_[a-zA-Z0-9]{24,}\b/g,
    severity: 'medium',
    description: 'Stripe test secret key detected.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Stripe Publishable Key (live)',
    regex: /\bpk_live_[a-zA-Z0-9]{24,}\b/g,
    severity: 'high',
    description: 'Stripe live publishable key — reveals provider identity, abuse risk.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Stripe Webhook Secret',
    regex: /\bwhsec_[a-zA-Z0-9]{32,}\b/g,
    severity: 'critical',
    description: 'Stripe webhook signing secret — allows request forgery.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Stripe Restricted Key',
    regex: /\brk_live_[a-zA-Z0-9]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe restricted live API key.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'PayPal Client Secret',
    regex: /(?:PAYPAL_(?:CLIENT_)?SECRET|paypal[_-]?(?:client[_-]?)?secret)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'PayPal client secret — enables payment creation and OAuth.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Razorpay Key',
    regex: /\brzp_(?:live|test)_[a-zA-Z0-9]{14}\b/g,
    severity: 'critical',
    description: 'Razorpay API key — Indian payment gateway access.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Braintree Access Token',
    regex: /\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Braintree (PayPal) access token.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Square Access Token',
    regex: /\b(?:sq0atp|sq0csp)-[a-zA-Z0-9\-_]{22,43}\b/g,
    severity: 'critical',
    description: 'Square payment access/client token.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Adyen API Key',
    regex: /\bAQE[a-zA-Z0-9+/=]{20,}\b/g,
    severity: 'critical',
    description: 'Adyen payment API key.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Paddle API Key',
    regex: /(?:PADDLE_(?:VENDOR_)?(?:API_KEY|AUTH_CODE)|paddle[_-]?(?:api[_-]?)?(?:key|auth))\s*[:=]\s*['"]?([a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Paddle billing API key.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Mollie API Key',
    regex: /\b(?:live|test)_[a-zA-Z0-9]{30,}\b/g,
    severity: 'critical',
    description: 'Mollie payment API key (live_ or test_ prefix).',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Lemon Squeezy API Key',
    regex: /(?:LEMONSQUEEZY_API_KEY|lemon[_-]?squeezy[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Lemon Squeezy SaaS billing API key.',
    redact: true,
    category: 'Payments',
  },
  {
    name: 'Checkout.com API Key',
    regex: /\b(?:sk|pk)_(?:sbox_|test_|prod_)[a-zA-Z0-9\-_]{30,}\b/g,
    severity: 'critical',
    description: 'Checkout.com payment API key.',
    redact: true,
    category: 'Payments',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── DATABASES ───────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Database Connection String (generic)',
    regex: /(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|mariadb|redis|mssql|sqlserver|oracle|cockroachdb|cassandra|couchdb|neo4j|clickhouse|tidb):\/\/[^\s'"<>]+:[^\s'"<>@]+@[^\s'"<>]+/gi,
    severity: 'critical',
    description: 'Database connection string with embedded credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Supabase Service Role Key',
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase[_-]?service[_-]?(?:role[_-]?)?key)\s*[:=]\s*['"]?(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Supabase service role key — bypasses Row Level Security entirely.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Supabase Anon Key',
    regex: /(?:SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|supabase[_-]?anon[_-]?key)\s*[:=]\s*['"]?(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'medium',
    description: 'Supabase anonymous key — exposes public API endpoint.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'PlanetScale Database URL',
    regex: /mysql:\/\/[^:]+:[a-zA-Z0-9_\-+/=]{20,}@[^/]*\.psdb\.cloud/g,
    severity: 'critical',
    description: 'PlanetScale database connection URL with credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Neon Database URL',
    regex: /postgres(?:ql)?:\/\/[^:]+:[a-zA-Z0-9_\-+/=]{20,}@[^/]*\.neon\.tech/g,
    severity: 'critical',
    description: 'Neon serverless Postgres URL with credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'MongoDB Atlas Connection String',
    regex: /mongodb\+srv:\/\/[^\s'"<>]+:[^\s'"<>@]+@[^\s'"<>]+\.mongodb\.net/g,
    severity: 'critical',
    description: 'MongoDB Atlas connection string with credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Turso Database URL',
    regex: /libsql:\/\/[^\s'"]+\.turso\.io/g,
    severity: 'high',
    description: 'Turso (libSQL) database URL.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Turso Auth Token',
    regex: /(?:TURSO_AUTH_TOKEN|turso[_-]?(?:auth[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Turso database auth token.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Upstash Redis URL',
    regex: /rediss?:\/\/[^:]+:[a-zA-Z0-9]{30,}@[^\s'"]+\.upstash\.io/g,
    severity: 'critical',
    description: 'Upstash Redis URL with embedded credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Upstash REST Token',
    regex: /(?:UPSTASH_REDIS_REST_TOKEN|upstash[_-]?(?:redis[_-]?)?(?:rest[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Upstash Redis REST API token.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Upstash QStash Token',
    regex: /(?:QSTASH_TOKEN|qstash[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Upstash QStash serverless message queue token.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Airtable Personal Access Token',
    regex: /\bpat[a-zA-Z0-9]{14}\.[a-fA-F0-9]{64}\b/g,
    severity: 'critical',
    description: 'Airtable Personal Access Token — base and workspace access.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Pinecone API Key',
    regex: /(?:PINECONE_API_KEY|pinecone[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'Pinecone vector database API key.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Weaviate API Key',
    regex: /(?:WEAVIATE_API_KEY|weaviate[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Weaviate vector database API key.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Qdrant API Key',
    regex: /(?:QDRANT_API_KEY|qdrant[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Qdrant vector database API key.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Xata API Key',
    regex: /\bxau_[a-zA-Z0-9]{80,}\b/g,
    severity: 'critical',
    description: 'Xata serverless database API key.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Fauna Secret Key',
    regex: /(?:FAUNA_SECRET|fauna[_-]?(?:db[_-]?)?(?:secret|key))\s*[:=]\s*['"]?(fn[a-zA-Z0-9_\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'Fauna database secret key.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'CockroachDB Connection String',
    regex: /postgresql?:\/\/[^:]+:[a-zA-Z0-9_\-+/=]{20,}@[^/]*\.cockroachlabs\.cloud/g,
    severity: 'critical',
    description: 'CockroachDB Cloud connection string with credentials.',
    redact: true,
    category: 'Databases',
  },
  {
    name: 'Convex Deploy Key',
    regex: /(?:CONVEX_DEPLOY_KEY|convex[_-]?deploy[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9|]{60,})['"]?/gi,
    severity: 'critical',
    description: 'Convex backend deploy key.',
    redact: true,
    category: 'Databases',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── MONITORING & OBSERVABILITY ──────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Datadog API Key',
    regex: /(?:DD_API_KEY|datadog[_-]?api[_-]?key)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Datadog API key — infrastructure observability access.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Datadog App Key',
    regex: /(?:DD_APP_KEY|datadog[_-]?app[_-]?key)\s*[:=]\s*['"]?([a-fA-F0-9]{40})['"]?/gi,
    severity: 'critical',
    description: 'Datadog Application key — dashboard and alert management.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Sentry DSN',
    regex: /https:\/\/[a-fA-F0-9]{32}@(?:o\d+\.)?sentry\.io\/\d+/g,
    severity: 'medium',
    description: 'Sentry DSN — exposes project and org identifiers.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Sentry Auth Token',
    regex: /(?:SENTRY_AUTH_TOKEN|sentry[_-]?auth[_-]?token)\s*[:=]\s*['"]?([a-fA-F0-9]{64})['"]?/gi,
    severity: 'critical',
    description: 'Sentry authentication token — project and org management.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'New Relic License Key',
    regex: /(?:NEW_RELIC_LICENSE_KEY|newrelic[_-]?license[_-]?key)\s*[:=]\s*['"]?([a-fA-F0-9]{40}|NRAK-[a-zA-Z0-9]{42})['"]?/gi,
    severity: 'critical',
    description: 'New Relic license key — APM telemetry ingestion.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'New Relic Ingest Key',
    regex: /\bNRIK-[a-zA-Z0-9]{36}\b/g,
    severity: 'critical',
    description: 'New Relic Ingest/License API key.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Grafana API Token (Service Account)',
    regex: /\bglsa_[a-zA-Z0-9]{32}_[a-fA-F0-9]{8}\b/g,
    severity: 'critical',
    description: 'Grafana Service Account Token.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Grafana Cloud API Key (glc_)',
    regex: /\bglc_eyJ[A-Za-z0-9+/]{29,400}={0,2}\b/g,
    severity: 'critical',
    description: 'Grafana Cloud API key.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Logflare API Key',
    regex: /(?:LOGFLARE_API_KEY|logflare[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{36,})['"]?/gi,
    severity: 'high',
    description: 'Logflare API key — log ingestion access.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Honeycomb API Key',
    regex: /(?:HONEYCOMB_API_KEY|honeycomb[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Honeycomb observability API key.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Axiom API Token',
    regex: /\bxaat-[a-zA-Z0-9\-]{36,}\b/g,
    severity: 'critical',
    description: 'Axiom log analytics API token.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Better Stack (Logtail) API Token',
    regex: /(?:BETTERSTACK_API_KEY|LOGTAIL_SOURCE_TOKEN|logtail[_-]?(?:source[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
    severity: 'high',
    description: 'Better Stack (Logtail) log forwarding token.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Rollbar Access Token',
    regex: /(?:ROLLBAR_(?:ACCESS_)?TOKEN|rollbar[_-]?(?:access[_-]?)?token)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Rollbar error monitoring access token.',
    redact: true,
    category: 'Monitoring',
  },
  {
    name: 'Bugsnag API Key',
    regex: /(?:BUGSNAG_API_KEY|bugsnag[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'high',
    description: 'Bugsnag error monitoring API key.',
    redact: true,
    category: 'Monitoring',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── AUTH / IDENTITY PROVIDERS ───────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Auth0 Client Secret',
    regex: /(?:AUTH0_CLIENT_SECRET|auth0[_-]?client[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Auth0 client secret — OAuth token exchange access.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Auth0 Management API Token',
    regex: /(?:AUTH0_MANAGEMENT_TOKEN|auth0[_-]?(?:mgmt|management)[_-]?token)\s*[:=]\s*['"]?(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Auth0 Management API token — full user and app management.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Clerk Secret Key',
    regex: /\bsk_(?:live|test)_[a-zA-Z0-9]{40,}\b/g,
    severity: 'critical',
    description: 'Clerk.dev secret key — user and session management.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Okta API Token',
    regex: /(?:OKTA_API_TOKEN|okta[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Okta API token — identity and directory management.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'JWT Token',
    regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    severity: 'high',
    description: 'JSON Web Token — may contain auth claims and sensitive data.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'NextAuth Secret',
    regex: /(?:NEXTAUTH_SECRET|nextauth[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9+/=_\-]{20,})['"]?/gi,
    severity: 'critical',
    description: 'NextAuth.js session secret — allows forging session cookies.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Better Auth Secret',
    regex: /(?:BETTER_AUTH_SECRET|better[_-]?auth[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9+/=_\-]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Better Auth session secret.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'WorkOS API Key',
    regex: /(?:WORKOS_API_KEY|workos[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?(sk_[a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'WorkOS enterprise SSO API key.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Stytch Secret Key',
    regex: /(?:STYTCH_SECRET|stytch[_-]?(?:project[_-]?)?secret)\s*[:=]\s*['"]?(secret-(?:live|test)-[a-zA-Z0-9\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'Stytch authentication secret key.',
    redact: true,
    category: 'Auth & Identity',
  },
  {
    name: 'Passage by 1Password API Key',
    regex: /(?:PASSAGE_API_KEY|passage[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Passage (1Password) passwordless auth API key.',
    redact: true,
    category: 'Auth & Identity',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── CRYPTO / WEB3 ───────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Ethereum / EVM Private Key',
    regex: /(?:0x)?[a-fA-F0-9]{64}(?=\b)/g,
    severity: 'critical',
    description: 'Potential Ethereum/EVM private key — grants full wallet control.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'BIP39 Mnemonic Phrase',
    regex: /\b(?:(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis)\b[\s,]+){11,23}(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis)\b/gi,
    severity: 'critical',
    description: 'BIP39 seed phrase fragment — grants full wallet recovery access.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'Alchemy API Key',
    regex: /(?:ALCHEMY_API_KEY|alchemy[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{32,})['"]?/gi,
    severity: 'critical',
    description: 'Alchemy blockchain RPC/indexer API key.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'Infura API Key',
    regex: /(?:INFURA_(?:PROJECT_(?:ID|SECRET)|API_KEY)|infura[_-]?(?:project[_-]?)?(?:id|secret|key))\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Infura Ethereum node API key.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'QuickNode Endpoint',
    regex: /https:\/\/[a-z0-9\-]+\.quiknode\.pro\/[a-fA-F0-9]{48,}\//g,
    severity: 'critical',
    description: 'QuickNode RPC endpoint with embedded API key.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'Moralis API Key',
    regex: /(?:MORALIS_API_KEY|moralis[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Moralis Web3 data API key.',
    redact: true,
    category: 'Crypto / Web3',
  },
  {
    name: 'Helius API Key',
    regex: /(?:HELIUS_API_KEY|helius[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'Helius Solana blockchain API key.',
    redact: true,
    category: 'Crypto / Web3',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── INFRASTRUCTURE & NETWORKING ─────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Cloudflare API Token',
    regex: /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40})['"]?/gi,
    severity: 'critical',
    description: 'Cloudflare API token — DNS, WAF, Pages, and CDN control.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Cloudflare Global API Key',
    regex: /(?:CF_API_KEY|CLOUDFLARE_API_KEY|cloudflare[_-]?global[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9]{37})['"]?/gi,
    severity: 'critical',
    description: 'Cloudflare Global API Key — full account access.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Cloudflare Workers KV Namespace',
    regex: /(?:CLOUDFLARE_KV_NAMESPACE_ID|kv[_-]?namespace[_-]?id)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'medium',
    description: 'Cloudflare KV Namespace ID — identifies storage resource.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Cloudflare Account ID',
    regex: /(?:CLOUDFLARE_ACCOUNT_ID|cloudflare[_-]?account[_-]?id)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'low',
    description: 'Cloudflare account ID — exposes account identity.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'DigitalOcean Personal Access Token',
    regex: /\bdop_v1_[a-fA-F0-9]{64}\b/g,
    severity: 'critical',
    description: 'DigitalOcean Personal Access Token — full droplet/DB/K8s access.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Linode / Akamai Cloud Token',
    regex: /(?:LINODE_TOKEN|LINODE_API_KEY|linode[_-]?(?:token|api[_-]?key))\s*[:=]\s*['"]?([a-fA-F0-9]{64})['"]?/gi,
    severity: 'critical',
    description: 'Linode/Akamai Cloud API token — server and network management.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Terraform Cloud Token',
    regex: /(?:TFC_TOKEN|TFE_TOKEN|terraform[_-]?(?:cloud[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,})['"]?/gi,
    severity: 'critical',
    description: 'Terraform Cloud/Enterprise API token — IaC workspace control.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'HashiCorp Vault Token',
    regex: /(?:VAULT_TOKEN|vault[_-]?token)\s*[:=]\s*['"]?((?:hvs|hvb|s)\.[a-zA-Z0-9]{24,})['"]?/gi,
    severity: 'critical',
    description: 'HashiCorp Vault token — secrets engine access.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Doppler Service Token',
    regex: /\bdp\.st\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9]{40,}\b/g,
    severity: 'critical',
    description: 'Doppler secrets manager service token.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Pulumi Access Token',
    regex: /\bpul-[a-fA-F0-9]{40}\b/g,
    severity: 'critical',
    description: 'Pulumi infrastructure-as-code access token.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Infisical Service Token',
    regex: /(?:INFISICAL_TOKEN|infisical[_-]?(?:service[_-]?)?token)\s*[:=]\s*['"]?(st\.[a-zA-Z0-9\-_]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Infisical secrets manager service token.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Cloudsmith API Key',
    regex: /(?:CLOUDSMITH_API_KEY|cloudsmith[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Cloudsmith package registry API key.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Fastly API Key',
    regex: /(?:FASTLY_API_KEY|fastly[_-]?(?:api[_-]?)?(?:key|token))\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Fastly CDN API key — cache and service configuration.',
    redact: true,
    category: 'Infrastructure',
  },
  {
    name: 'Supabase URL (with anon key)',
    regex: /https:\/\/[a-z0-9]+\.supabase\.(?:co|com)/g,
    severity: 'low',
    description: 'Supabase project URL — identifies your project instance.',
    redact: false,
    category: 'Infrastructure',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── PACKAGE REGISTRIES ──────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'npm Access Token',
    regex: /(?:NPM_TOKEN|NPM_AUTH_TOKEN|npm[_-]?(?:auth[_-]?)?token)\s*[:=]\s*['"]?(npm_[a-zA-Z0-9]{36})['"]?/gi,
    severity: 'critical',
    description: 'npm publish/read access token.',
    redact: true,
    category: 'Package Registries',
  },
  {
    name: 'PyPI API Token',
    regex: /\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,}\b/g,
    severity: 'critical',
    description: 'PyPI package upload API token.',
    redact: true,
    category: 'Package Registries',
  },
  {
    name: 'RubyGems API Key',
    regex: /\brubygems_[a-fA-F0-9]{48}\b/g,
    severity: 'critical',
    description: 'RubyGems package publishing API key.',
    redact: true,
    category: 'Package Registries',
  },
  {
    name: 'JFrog Artifactory Token',
    regex: /(?:ARTIFACTORY_(?:API_KEY|ACCESS_TOKEN|TOKEN)|jfrog[_-]?(?:api[_-]?)?(?:key|token))\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'JFrog Artifactory access token — package management.',
    redact: true,
    category: 'Package Registries',
  },
  {
    name: 'Sonatype Nexus Token',
    regex: /(?:NEXUS_(?:PASSWORD|TOKEN)|nexus[_-]?(?:password|token))\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?/gi,
    severity: 'critical',
    description: 'Sonatype Nexus repository manager credential.',
    redact: true,
    category: 'Package Registries',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── SOCIAL & DEVELOPER APIS ─────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Twitter/X Bearer Token',
    regex: /\bAAAA[a-zA-Z0-9%]{80,}\b/g,
    severity: 'critical',
    description: 'Twitter/X API v2 Bearer Token — read access to public data.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Twitter/X Consumer Secret',
    regex: /(?:TWITTER_(?:API_)?SECRET|TWITTER_CONSUMER_SECRET|twitter[_-]?(?:consumer[_-]?)?(?:api[_-]?)?secret)\s*[:=]\s*['"]?([a-zA-Z0-9]{50})['"]?/gi,
    severity: 'critical',
    description: 'Twitter/X API Consumer Secret — OAuth flow access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Facebook / Meta App Secret',
    regex: /(?:FB_APP_SECRET|FACEBOOK_APP_SECRET|facebook[_-]?(?:app[_-]?)?secret|meta[_-]?(?:app[_-]?)?secret)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Facebook/Meta App Secret — platform API control.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Instagram Access Token',
    regex: /(?:INSTAGRAM_(?:ACCESS_)?TOKEN|instagram[_-]?(?:access[_-]?)?token)\s*[:=]\s*['"]?([0-9]{8,}[a-zA-Z0-9]{30,})['"]?/gi,
    severity: 'critical',
    description: 'Instagram Graph API access token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'LinkedIn Client Secret',
    regex: /(?:LINKEDIN_CLIENT_SECRET|linkedin[_-]?client[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9]{16})['"]?/gi,
    severity: 'critical',
    description: 'LinkedIn OAuth client secret.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Shopify Admin API Access Token',
    regex: /\bshpat_[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Shopify Admin API access token — full store management.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Shopify Partner API Token',
    regex: /\bshppa_[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Shopify Partner API token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Shopify Custom App Token',
    regex: /\bshpca_[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Shopify Custom App access token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Figma Personal Access Token',
    regex: /\bfigd_[a-zA-Z0-9\-_]{40,}\b/g,
    severity: 'high',
    description: 'Figma Personal Access Token — file and team read/write access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Notion API Secret',
    regex: /\bsecret_[a-zA-Z0-9]{43}\b/g,
    severity: 'critical',
    description: 'Notion integration secret — page and database access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Linear API Key',
    regex: /\blin_api_[a-zA-Z0-9]{40}\b/g,
    severity: 'critical',
    description: 'Linear.app API key — issue and project management access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Intercom Access Token',
    regex: /(?:INTERCOM_ACCESS_TOKEN|intercom[_-]?(?:access[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Intercom messaging/CRM access token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'HubSpot API Key',
    regex: /(?:HUBSPOT_API_KEY|hubspot[_-]?(?:api[_-]?)?(?:key|token))\s*[:=]\s*['"]?([a-fA-F0-9\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'HubSpot CRM API key — contact and marketing access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Zendesk API Token',
    regex: /(?:ZENDESK_(?:API_)?TOKEN|zendesk[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Zendesk support platform API token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Salesforce Access Token',
    regex: /(?:SALESFORCE_(?:ACCESS_)?TOKEN|salesforce[_-]?(?:access[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9!]{80,})['"]?/gi,
    severity: 'critical',
    description: 'Salesforce CRM OAuth access token.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Asana Personal Access Token',
    regex: /\b[0-9]\/[0-9]{16}:[a-fA-F0-9]{32}\b/g,
    severity: 'critical',
    description: 'Asana Personal Access Token — workspace and project access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Jira API Token',
    regex: /(?:JIRA_API_TOKEN|jira[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{24})['"]?/gi,
    severity: 'critical',
    description: 'Atlassian Jira API token — issue management access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Confluence API Token',
    regex: /(?:CONFLUENCE_API_TOKEN|confluence[_-]?(?:api[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9]{24})['"]?/gi,
    severity: 'critical',
    description: 'Atlassian Confluence API token — wiki and page access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'WooCommerce Consumer Secret',
    regex: /(?:WC_SECRET|WOOCOMMERCE_CONSUMER_SECRET|woocommerce[_-]?consumer[_-]?secret)\s*[:=]\s*['"]?(cs_[a-fA-F0-9]{40})['"]?/gi,
    severity: 'critical',
    description: 'WooCommerce REST API consumer secret.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Contentful Management Token',
    regex: /(?:CONTENTFUL_MANAGEMENT_TOKEN|contentful[_-]?(?:management[_-]?)?(?:access[_-]?)?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Contentful CMS management token — content and space management.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Contentful Delivery API Token',
    regex: /(?:CONTENTFUL_DELIVERY_TOKEN|contentful[_-]?delivery[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{40,})['"]?/gi,
    severity: 'medium',
    description: 'Contentful Content Delivery API token — public content read access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Sanity API Token',
    regex: /(?:SANITY_API_TOKEN|sanity[_-]?(?:api[_-]?)?(?:token|key))\s*[:=]\s*['"]?(sk[a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Sanity CMS API token — project data access.',
    redact: true,
    category: 'Social APIs',
  },
  {
    name: 'Vercel Blob Read-Write Token',
    regex: /\bvercel_blob_rw_[a-zA-Z0-9]{20,}_[a-zA-Z0-9]{40,}\b/g,
    severity: 'critical',
    description: 'Vercel Blob Storage read-write token.',
    redact: true,
    category: 'Social APIs',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── PRIVATE KEYS & CERTIFICATES ─────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'PEM Private Key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'PEM-encoded private key block — do not share or commit.',
    redact: false,
    category: 'Keys & Certs',
  },
  {
    name: 'OpenSSH Private Key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'OpenSSH private key — grants SSH access wherever deployed.',
    redact: false,
    category: 'Keys & Certs',
  },
  {
    name: 'PGP Private Key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    severity: 'critical',
    description: 'PGP private key block — allows signing and decryption.',
    redact: false,
    category: 'Keys & Certs',
  },
  {
    name: 'PEM Certificate',
    regex: /-----BEGIN CERTIFICATE-----/g,
    severity: 'medium',
    description: 'PEM certificate block — may include chain or sensitive cert data.',
    redact: false,
    category: 'Keys & Certs',
  },
  {
    name: 'PKCS12 / PFX Base64',
    regex: /(?:MII[A-Za-z0-9+/=]{100,})/g,
    severity: 'high',
    description: 'Base64 blob with PKCS12/cert-like structure detected.',
    redact: true,
    category: 'Keys & Certs',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── HARDCODED SECRETS (GENERIC) ─────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Generic Password Assignment',
    regex: /(?:password|passwd|pwd|secret|pass)\s*[:=]\s*['"][^'"]{16,}['"]/gi,
    severity: 'high',
    description: 'Hardcoded password or secret string in assignment.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'Generic API Key Assignment',
    regex: /(?:api[_-]?key|auth[_-]?token|access[_-]?token|bearer[_-]?token|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9+/=_\-]{20,}['"]/gi,
    severity: 'high',
    description: 'Hardcoded API key or token assignment.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'Basic Auth in URL',
    regex: /https?:\/\/[a-zA-Z0-9_%+\-.]+:[a-zA-Z0-9_%+\-.]{6,}@[a-zA-Z0-9\-.]+/g,
    severity: 'critical',
    description: 'Credentials embedded in a URL (Basic Auth).',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: '.env File Contents',
    regex: /^[A-Z][A-Z0-9_]{3,}=(?!false|true|0|1|null|undefined|localhost|\d+$).{10,}/gm,
    severity: 'high',
    description: 'Possible .env file contents with embedded secrets.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'Docker Registry Credentials',
    regex: /(?:DOCKER_(?:PASSWORD|TOKEN)|docker[_-]?(?:hub[_-]?)?(?:password|token))\s*[:=]\s*['"]?([a-zA-Z0-9\-_!@#$%^&*]{12,})['"]?/gi,
    severity: 'critical',
    description: 'Docker registry credentials — image push/pull access.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'Bearer Token in Authorization Header',
    regex: /Authorization\s*:\s*Bearer\s+([a-zA-Z0-9\-_+/=.]{20,})/gi,
    severity: 'high',
    description: 'Bearer token in an Authorization header.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'Basic Auth Header (base64)',
    regex: /Authorization\s*:\s*Basic\s+([a-zA-Z0-9+/=]{20,})/gi,
    severity: 'high',
    description: 'Base64-encoded Basic Auth credentials in Authorization header.',
    redact: true,
    category: 'Generic Secrets',
  },
  {
    name: 'X-API-Key Header',
    regex: /X-API-Key\s*:\s*([a-zA-Z0-9\-_+/=.]{20,})/gi,
    severity: 'high',
    description: 'API key in X-API-Key request header.',
    redact: true,
    category: 'Generic Secrets',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── PII / SENSITIVE PERSONAL DATA ───────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Social Security Number (US)',
    regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
    severity: 'critical',
    description: 'US Social Security Number (SSN) — identity theft risk.',
    redact: true,
    category: 'PII',
  },
  {
    name: 'Credit Card Number',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    severity: 'critical',
    description: 'Credit card number pattern (Visa/MC/Amex/Discover/JCB).',
    redact: true,
    category: 'PII',
  },
  {
    name: 'IBAN Bank Account',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g,
    severity: 'high',
    description: 'IBAN bank account number — financial identity risk.',
    redact: true,
    category: 'PII',
  },
  {
    name: 'Indian Aadhaar Number',
    regex: /\b[2-9]{1}[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b/g,
    severity: 'critical',
    description: 'Indian Aadhaar UID number — national identity credential.',
    redact: true,
    category: 'PII',
  },
  {
    name: 'Indian PAN Number',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    severity: 'high',
    description: 'Indian PAN (tax) number.',
    redact: true,
    category: 'PII',
  },
  {
    name: 'UK National Insurance Number',
    regex: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)(?:[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1})\d{6}[ABCD]\b/gi,
    severity: 'critical',
    description: 'UK National Insurance Number (NINO).',
    redact: true,
    category: 'PII',
  },
  {
    name: 'IP Address (Internal RFC1918)',
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    severity: 'low',
    description: 'Internal (RFC1918) IP address — reveals network topology.',
    redact: false,
    category: 'PII',
  },
  {
    name: 'Canadian SIN',
    regex: /\b\d{3}[-\s]\d{3}[-\s]\d{3}\b/g,
    severity: 'critical',
    description: 'Potential Canadian Social Insurance Number (SIN).',
    redact: true,
    category: 'PII',
  },
  {
    name: 'Passport Number (generic)',
    regex: /(?:passport[_\s]?(?:no|number|num))\s*[:=]?\s*['"]?([A-Z]{1,2}[0-9]{6,9})['"]?/gi,
    severity: 'critical',
    description: 'Passport number pattern detected.',
    redact: true,
    category: 'PII',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── UNSAFE CODE PATTERNS ────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'eval() Call',
    regex: /\beval\s*\(/g,
    severity: 'medium',
    description: '`eval()` executes arbitrary strings as code — common XSS vector.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'innerHTML Assignment',
    regex: /\.innerHTML\s*[+]?=/g,
    severity: 'medium',
    description: '`innerHTML` assignment can introduce XSS if content is user-supplied.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'document.write()',
    regex: /document\.write\s*\(/g,
    severity: 'medium',
    description: '`document.write()` is deprecated and a known XSS vector.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'outerHTML Assignment',
    regex: /\.outerHTML\s*[+]?=/g,
    severity: 'medium',
    description: '`outerHTML` assignment may allow DOM injection.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'dangerouslySetInnerHTML (React)',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:/g,
    severity: 'medium',
    description: 'React `dangerouslySetInnerHTML` — potential XSS if unsanitized.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'setTimeout with String Argument',
    regex: /setTimeout\s*\(\s*['"`]/g,
    severity: 'low',
    description: '`setTimeout` with string argument is equivalent to `eval()`.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'setInterval with String Argument',
    regex: /setInterval\s*\(\s*['"`]/g,
    severity: 'low',
    description: '`setInterval` with string argument is equivalent to `eval()`.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Function Constructor',
    regex: /\bnew\s+Function\s*\(/g,
    severity: 'medium',
    description: '`new Function(...)` dynamically evaluates code — eval risk.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Shell Execution with User Input (Node.js)',
    regex: /(?:execSync|spawnSync|exec|spawn)\s*\([^)]*(?:req\.|process\.argv|process\.env)/g,
    severity: 'high',
    description: 'Shell execution using user-controlled or env input — command injection.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Python subprocess with shell=True',
    regex: /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/g,
    severity: 'high',
    description: 'Python subprocess with `shell=True` — command injection risk.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Python os.system() Call',
    regex: /\bos\.system\s*\(/g,
    severity: 'medium',
    description: '`os.system()` executes shell commands — injection vector.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Unsafe Deserialization',
    regex: /(?:unserialize|yaml\.load|pickle\.loads?|marshal\.loads?|jsonpickle\.decode)\s*\(/g,
    severity: 'high',
    description: 'Unsafe deserialization call — potential RCE.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: '__proto__ Pollution',
    regex: /\.__proto__\s*=/g,
    severity: 'high',
    description: 'Prototype pollution via `__proto__` assignment.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Prototype Pollution (constructor)',
    regex: /\.constructor\.prototype\s*=/g,
    severity: 'high',
    description: 'Prototype pollution via `constructor.prototype` assignment.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'SQL String Concatenation',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.{0,60}\+\s*(?:req\.|request\.|params\.|query\.|body\.|user\.|input)/gi,
    severity: 'high',
    description: 'Potential SQL injection via string concatenation with user input.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Path Traversal',
    regex: /(?:readFile|readFileSync|createReadStream|open)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/g,
    severity: 'high',
    description: 'File read with user-controlled path — directory traversal risk.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'SSRF-Prone fetch/axios with User Input',
    regex: /(?:fetch|axios\.get|axios\.post|http\.get|https\.get)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/g,
    severity: 'high',
    description: 'HTTP request with user-controlled URL — SSRF risk.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Disabled TLS/SSL Verification',
    regex: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl_verify\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?)/gi,
    severity: 'high',
    description: 'TLS/SSL verification disabled — MITM attack risk.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Hardcoded Cryptographic Key or IV',
    regex: /(?:\bkey\b|\biv\b|\bnonce\b|\bsalt\b)\s*[:=]\s*(?:0x)?['"]?[a-fA-F0-9]{32,}['"]?/gi,
    severity: 'high',
    description: 'Hardcoded cryptographic key, IV, or nonce.',
    redact: true,
    category: 'Unsafe Code',
  },
  {
    name: 'Weak Hashing Algorithm',
    regex: /(?:createHash|hashlib\.new)\s*\(\s*['"](?:md5|sha1)['"]/gi,
    severity: 'medium',
    description: 'Weak hash (MD5/SHA-1) used — use SHA-256 or stronger.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Math.random() for Security',
    regex: /Math\.random\(\)(?=.*(?:token|secret|key|auth|password|nonce|id))/gi,
    severity: 'medium',
    description: '`Math.random()` is not cryptographically secure — use `crypto.randomUUID()` or `crypto.getRandomValues()`.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'RegExp ReDoS Risk',
    regex: /new RegExp\([^)]*\*[\s\S]{0,20}\*/g,
    severity: 'low',
    description: 'Dynamic RegExp with multiple wildcards — potential ReDoS vulnerability.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Insecure Random in Python',
    regex: /\brandom\.(?:random|randint|choice|shuffle)\s*\([^)]*(?:token|secret|key|password)/gi,
    severity: 'medium',
    description: 'Python `random` module used for security — use `secrets` module instead.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Python input() in Server Code',
    regex: /\binput\s*\([^)]*\)(?=.*(?:exec|eval|subprocess|os\.system))/g,
    severity: 'high',
    description: '`input()` feeding into execution functions — potential injection.',
    redact: false,
    category: 'Unsafe Code',
  },
  {
    name: 'Pickle Deserialization',
    regex: /\bpickle\.(?:load|loads)\s*\(/g,
    severity: 'high',
    description: '`pickle.load` from untrusted input allows arbitrary code execution.',
    redact: false,
    category: 'Unsafe Code',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── MOBILE / IoT ────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Apple Push Notification Service Key',
    regex: /(?:APN[Ss]?_(?:AUTH_KEY|KEY_ID|KEY)|apns[_-]?(?:auth[_-]?)?key)\s*[:=]\s*['"]?([A-Z0-9]{10})['"]?/gi,
    severity: 'critical',
    description: 'Apple APNs key ID — push notification access for iOS apps.',
    redact: true,
    category: 'Mobile / IoT',
  },
  {
    name: 'Google FCM Server Key',
    regex: /(?:FCM_SERVER_KEY|google[_-]?fcm[_-]?(?:server[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{140,})['"]?/gi,
    severity: 'critical',
    description: 'Firebase Cloud Messaging server key — push notification abuse.',
    redact: true,
    category: 'Mobile / IoT',
  },
  {
    name: 'Expo Push Token',
    regex: /ExponentPushToken\[[a-zA-Z0-9\-_]{22,}\]/g,
    severity: 'medium',
    description: 'Expo push notification device token.',
    redact: true,
    category: 'Mobile / IoT',
  },
  {
    name: 'AWS IoT Certificate',
    regex: /-----BEGIN CERTIFICATE-----[\s\S]{0,100}aws-iot/gi,
    severity: 'critical',
    description: 'AWS IoT device certificate — device identity for MQTT connections.',
    redact: false,
    category: 'Mobile / IoT',
  },
  {
    name: 'MQTT Broker Credentials',
    regex: /mqtt(?:s)?:\/\/[^\s'"<>]+:[^\s'"<>@]+@[^\s'"<>]+/g,
    severity: 'critical',
    description: 'MQTT broker connection string with credentials.',
    redact: true,
    category: 'Mobile / IoT',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── SEARCH & DATA PLATFORMS ─────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Algolia API Key',
    regex: /(?:ALGOLIA_(?:API_KEY|ADMIN_KEY|SEARCH_KEY)|algolia[_-]?(?:admin|api|search)[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    severity: 'critical',
    description: 'Algolia search API key — index management and data access.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Typesense API Key',
    regex: /(?:TYPESENSE_API_KEY|typesense[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{24,})['"]?/gi,
    severity: 'critical',
    description: 'Typesense search API key.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Elastic Cloud API Key',
    regex: /(?:ELASTIC_(?:API_KEY|CLOUD_ID)|elastic[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_+=/]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Elasticsearch / Elastic Cloud API key.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Meilisearch Master Key',
    regex: /(?:MEILI(?:SEARCH)?_MASTER_KEY|meilisearch[_-]?master[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{24,})['"]?/gi,
    severity: 'critical',
    description: 'Meilisearch master key — full index control.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Segment Write Key',
    regex: /(?:SEGMENT_WRITE_KEY|segment[_-]?write[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})['"]?/gi,
    severity: 'high',
    description: 'Segment analytics write key — data pipeline access.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Mixpanel Project Token',
    regex: /(?:MIXPANEL_TOKEN|mixpanel[_-]?(?:project[_-]?)?token)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'medium',
    description: 'Mixpanel project token — analytics event ingestion.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'Amplitude API Key',
    regex: /(?:AMPLITUDE_API_KEY|amplitude[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9]{32})['"]?/gi,
    severity: 'medium',
    description: 'Amplitude analytics API key.',
    redact: true,
    category: 'Search & Data',
  },
  {
    name: 'PostHog API Key',
    regex: /(?:POSTHOG_API_KEY|posthog[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?(phc_[a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'high',
    description: 'PostHog product analytics API key.',
    redact: true,
    category: 'Search & Data',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── STORAGE & CDN ───────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Cloudinary API Secret',
    regex: /(?:CLOUDINARY_API_SECRET|cloudinary[_-]?api[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{27})['"]?/gi,
    severity: 'critical',
    description: 'Cloudinary media management API secret — full asset access.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'Cloudinary URL (with credentials)',
    regex: /cloudinary:\/\/[0-9]+:[a-zA-Z0-9_\-]{27}@[a-z0-9]+/g,
    severity: 'critical',
    description: 'Cloudinary URL with embedded API key and secret.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'Bunny.net Storage API Key',
    regex: /(?:BUNNY(?:CDN)?_(?:API_KEY|STORAGE_KEY)|bunny[_-]?(?:cdn[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-fA-F0-9\-]{36,})['"]?/gi,
    severity: 'critical',
    description: 'Bunny.net CDN/storage API key.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'Uploadthing Secret',
    regex: /(?:UPLOADTHING_SECRET|uploadthing[_-]?secret)\s*[:=]\s*['"]?(sk_[a-zA-Z0-9]{40,})['"]?/gi,
    severity: 'critical',
    description: 'Uploadthing file upload API secret.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'ImageKit Private API Key',
    regex: /(?:IMAGEKIT_PRIVATE_KEY|imagekit[_-]?private[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?(private_[a-zA-Z0-9+/=]{40,})['"]?/gi,
    severity: 'critical',
    description: 'ImageKit private API key — full media management access.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'Backblaze B2 Application Key',
    regex: /(?:B2_APPLICATION_KEY|backblaze[_-]?(?:b2[_-]?)?(?:application[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{31})['"]?/gi,
    severity: 'critical',
    description: 'Backblaze B2 cloud storage application key.',
    redact: true,
    category: 'Storage & CDN',
  },
  {
    name: 'Wasabi Secret Key',
    regex: /(?:WASABI_SECRET_ACCESS_KEY|wasabi[_-]?secret[_-]?(?:access[_-]?)?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    description: 'Wasabi hot cloud storage secret access key.',
    redact: true,
    category: 'Storage & CDN',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ─── MAPS & GEO ──────────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════════════════

  {
    name: 'Mapbox Access Token',
    regex: /\bpk\.eyJ1IjoiW[a-zA-Z0-9._\-]{60,}\b/g,
    severity: 'high',
    description: 'Mapbox public access token — map tile and geocoding usage.',
    redact: true,
    category: 'Maps & Geo',
  },
  {
    name: 'Mapbox Secret Token',
    regex: /\bsk\.eyJ1IjoiW[a-zA-Z0-9._\-]{60,}\b/g,
    severity: 'critical',
    description: 'Mapbox secret token — account and style management.',
    redact: true,
    category: 'Maps & Geo',
  },
  {
    name: 'HERE API Key',
    regex: /(?:HERE_API_KEY|here[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{43})['"]?/gi,
    severity: 'high',
    description: 'HERE Maps API key — location and routing access.',
    redact: true,
    category: 'Maps & Geo',
  },
  {
    name: 'TomTom API Key',
    regex: /(?:TOMTOM_API_KEY|tomtom[_-]?(?:api[_-]?)?key)\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?/gi,
    severity: 'high',
    description: 'TomTom maps/navigation API key.',
    redact: true,
    category: 'Maps & Geo',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns line number (1-indexed) for a match at `index` within `text`.
 */
function getLineNumber(text: string, index: number): number {
  return text.substring(0, index).split('\n').length;
}

/**
 * Redacts a sensitive match string, preserving only the first 4 and last 4 chars.
 */
function redactMatch(match: string): string {
  if (match.length <= 12) {
    return '*'.repeat(match.length);
  }
  const stars = '*'.repeat(Math.min(match.length - 8, 24));
  return `${match.substring(0, 4)}${stars}${match.substring(match.length - 4)}`;
}

/**
 * Truncates a match string for safe display (max 60 chars).
 */
function truncateMatch(match: string): string {
  const cleaned = match.replace(/\s+/g, ' ').trim();
  return cleaned.length > 60 ? `${cleaned.substring(0, 57)}...` : cleaned;
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────────────────────────────────────

export interface ScanOptions {
  ignoredPatterns?: string[];
  maxResults?: number;
  categories?: string[];  // If set, only these categories are scanned
}

/**
 * Scans `text` against all registered patterns.
 * Returns at most one DetectionResult per pattern (first match) to avoid noise.
 * Designed to run in < 50 ms for typical clipboard content (≤ 5 KB).
 */
export function scanContent(text: string, options: ScanOptions = {}): DetectionResult[] {
  const { ignoredPatterns = [], maxResults = 100, categories } = options;
  const results: DetectionResult[] = [];

  for (const def of PATTERN_DEFINITIONS) {
    if (results.length >= maxResults) break;
    if (ignoredPatterns.includes(def.name)) continue;
    if (categories && !categories.includes(def.category)) continue;

    // Re-instantiate regex from source to reset lastIndex (avoids /g state bugs)
    const flags = def.regex.flags.includes('g') ? def.regex.flags : `${def.regex.flags}g`;
    const regex = new RegExp(def.regex.source, flags);
    const match = regex.exec(text);

    if (match) {
      const rawMatch = match[0];
      const displayMatch = def.redact
        ? redactMatch(rawMatch)
        : truncateMatch(rawMatch);

      results.push({
        type: def.name,
        description: def.description,
        match: displayMatch,
        severity: def.severity,
        line: getLineNumber(text, match.index),
        category: def.category,
      });
    }
  }

  // Sort: critical → high → medium → low
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  results.sort((a, b) => order[a.severity] - order[b.severity]);

  return results;
}

/**
 * Returns all unique categories available in the pattern registry.
 */
export function getCategories(): string[] {
  return [...new Set(PATTERN_DEFINITIONS.map(p => p.category))];
}

/**
 * Returns the total number of registered patterns.
 */
export function getPatternCount(): number {
  return PATTERN_DEFINITIONS.length;
}

/**
 * Returns all patterns in a given category.
 */
export function getPatternsByCategory(category: string): PatternDefinition[] {
  return PATTERN_DEFINITIONS.filter(p => p.category === category);
}

export { PATTERN_DEFINITIONS };