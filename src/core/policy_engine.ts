import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import {
  AuditEnvironment,
  AuditFinding,
  BaselineEntry,
  CoreCheckBaseline,
  PolicyEvaluationResult,
  SeverityLevel
} from '../types/audit.js';

const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

/** Fail-on por defecto según entorno (prod más estricto). */
const ENV_FAIL_ON: Record<AuditEnvironment, SeverityLevel> = {
  prod: 'HIGH',
  staging: 'CRITICAL',
  dev: 'CRITICAL'
};

/**
 * Motor de políticas y baselines:
 * - umbrales por entorno (prod / staging / dev)
 * - suppressions vía `.corecheckignore` o baseline JSON
 */
export class PolicyEngine {
  constructor(
    private readonly environment: AuditEnvironment = 'prod',
    private readonly baselineEntries: BaselineEntry[] = []
  ) {}

  public static async fromPaths(options: {
    environment?: AuditEnvironment;
    baselinePath?: string;
    cwd?: string;
  }): Promise<PolicyEngine> {
    const env = options.environment ?? 'prod';
    const cwd = options.cwd ?? process.cwd();
    const entries: BaselineEntry[] = [];

    const explicit = options.baselinePath
      ? path.resolve(options.baselinePath)
      : undefined;
    const ignorePath = path.join(cwd, '.corecheckignore');
    const defaultBaseline = path.join(cwd, 'corecheck-baseline.json');

    if (explicit) {
      entries.push(...(await PolicyEngine.loadBaselineFile(explicit)));
    } else {
      try {
        await fs.access(ignorePath);
        entries.push(...(await PolicyEngine.loadBaselineFile(ignorePath)));
      } catch {
        // optional
      }
      try {
        await fs.access(defaultBaseline);
        entries.push(...(await PolicyEngine.loadBaselineFile(defaultBaseline)));
      } catch {
        // optional
      }
    }

    return new PolicyEngine(env, entries);
  }

  public static async loadBaselineFile(filePath: string): Promise<BaselineEntry[]> {
    const raw = await fs.readFile(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.json' || filePath.endsWith('corecheck-baseline.json')) {
      const parsed = JSON.parse(raw) as CoreCheckBaseline | BaselineEntry[];
      if (Array.isArray(parsed)) {
        return parsed;
      }
      return parsed.accepted ?? [];
    }

    // .corecheckignore — una regla por línea: ruleId[|selector][|url]  # comment
    return raw
      .split(/\r?\n/)
      .map((line) => line.replace(/#.*$/, '').trim())
      .filter(Boolean)
      .map((line) => {
        const [ruleId, selector, url] = line.split('|').map((p) => p.trim());
        return {
          ruleId,
          ...(selector ? { selector } : {}),
          ...(url ? { url } : {})
        } satisfies BaselineEntry;
      });
  }

  public resolveFailOn(cliFailOn?: SeverityLevel): SeverityLevel {
    if (cliFailOn) {
      return cliFailOn;
    }
    return ENV_FAIL_ON[this.environment];
  }

  public evaluate(
    findings: AuditFinding[],
    failOn: SeverityLevel
  ): PolicyEvaluationResult {
    const activeFindings: AuditFinding[] = [];
    const suppressedFindings: AuditFinding[] = [];

    for (const finding of findings) {
      if (this.isSuppressed(finding)) {
        suppressedFindings.push(finding);
      } else {
        activeFindings.push(finding);
      }
    }

    const minWeight = SEVERITY_WEIGHTS[failOn];
    const gateFailed = activeFindings.some(
      (f) => (SEVERITY_WEIGHTS[f.severity] ?? 0) >= minWeight
    );

    return {
      environment: this.environment,
      failOn,
      gateFailed,
      suppressedCount: suppressedFindings.length,
      activeFindings,
      suppressedFindings
    };
  }

  public isSuppressed(finding: AuditFinding): boolean {
    return this.baselineEntries.some((entry) => this.matchesEntry(finding, entry));
  }

  private matchesEntry(finding: AuditFinding, entry: BaselineEntry): boolean {
    if (entry.ruleId !== finding.ruleId && entry.ruleId !== '*') {
      // glob simple: SEC-* 
      if (entry.ruleId.endsWith('*')) {
        const prefix = entry.ruleId.slice(0, -1);
        if (!finding.ruleId.startsWith(prefix)) {
          return false;
        }
      } else {
        return false;
      }
    }

    if (entry.selector) {
      const sel = finding.evidence.selector ?? '';
      if (sel !== entry.selector && !sel.includes(entry.selector)) {
        return false;
      }
    }

    if (entry.url) {
      const url = finding.evidence.url ?? '';
      if (url !== entry.url && !url.includes(entry.url)) {
        return false;
      }
    }

    return true;
  }
}
