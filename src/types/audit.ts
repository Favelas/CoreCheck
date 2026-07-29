export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type OutputFormat = 'json' | 'sarif' | 'html';

export interface AuditFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  evidence: {
    selector?: string;
    snippet?: string;
    requestPayload?: string;
    responseStatus?: number;
    responseHeaders?: Record<string, string>;
    screenshotPath?: string;
  };
  remediation: {
    explanation: string;
    codeBefore?: string;
    codeAfter?: string;
  };
  standards: {
    owasp?: string[];
    wcag?: string[];
    cwe?: string[];
  };
}

export interface AuditExecutionOptions {
  targetUrl: string;
  storageStatePath?: string;
  concurrency?: number;
  timeoutMs?: number;
  maxRetries?: number;
  outputFormats?: OutputFormat[];
  activeFuzzing?: boolean;
}