/**
 * Validador estructural SARIF 2.1.0 (subset OASIS + requisitos GitHub Code Scanning).
 * No sustituye un validador JSON Schema completo offline, pero garantiza que el
 * documento exportado sea parseable y conforme al contrato que consumen GHAS/GitLab.
 */

export interface SarifValidationIssue {
  path: string;
  message: string;
}

export interface SarifValidationResult {
  ok: boolean;
  issues: SarifValidationIssue[];
}

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA_URI =
  'https://raw.githubusercontent.com/oasis-tccs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function push(
  issues: SarifValidationIssue[],
  path: string,
  message: string
): void {
  issues.push({ path, message });
}

/**
 * Valida un documento SARIF generado por CoreCheck contra el contrato 2.1.0
 * requerido por OASIS (campos obligatorios) y GitHub Code Scanning.
 */
export function validateSarifDocument(doc: unknown): SarifValidationResult {
  const issues: SarifValidationIssue[] = [];

  if (!isRecord(doc)) {
    return { ok: false, issues: [{ path: '$', message: 'Root must be a JSON object' }] };
  }

  if (doc.version !== SARIF_VERSION) {
    push(issues, '$.version', `Expected "${SARIF_VERSION}", got ${String(doc.version)}`);
  }

  if (typeof doc.$schema !== 'string' || !doc.$schema.includes('sarif-schema-2.1.0')) {
    push(
      issues,
      '$.$schema',
      `Expected SARIF 2.1.0 schema URI containing "sarif-schema-2.1.0" (canonical: ${SARIF_SCHEMA_URI})`
    );
  }

  if (!Array.isArray(doc.runs) || doc.runs.length < 1) {
    push(issues, '$.runs', 'Must be a non-empty array');
    return { ok: false, issues };
  }

  doc.runs.forEach((run, runIndex) => {
    const runPath = `$.runs[${runIndex}]`;
    if (!isRecord(run)) {
      push(issues, runPath, 'Run must be an object');
      return;
    }

    if (!isRecord(run.tool) || !isRecord(run.tool.driver)) {
      push(issues, `${runPath}.tool.driver`, 'tool.driver is required');
      return;
    }

    const driver = run.tool.driver;
    if (typeof driver.name !== 'string' || driver.name.length === 0) {
      push(issues, `${runPath}.tool.driver.name`, 'driver.name is required');
    }
    if (typeof driver.version !== 'string' || driver.version.length === 0) {
      push(issues, `${runPath}.tool.driver.version`, 'driver.version is required');
    }

    if (!Array.isArray(driver.rules)) {
      push(issues, `${runPath}.tool.driver.rules`, 'rules must be an array');
    } else {
      driver.rules.forEach((rule, ruleIndex) => {
        const rulePath = `${runPath}.tool.driver.rules[${ruleIndex}]`;
        if (!isRecord(rule)) {
          push(issues, rulePath, 'rule must be an object');
          return;
        }
        if (typeof rule.id !== 'string' || !rule.id) {
          push(issues, `${rulePath}.id`, 'rule.id is required');
        }
        if (!isRecord(rule.shortDescription) || typeof rule.shortDescription.text !== 'string') {
          push(issues, `${rulePath}.shortDescription.text`, 'shortDescription.text is required');
        }
        if (isRecord(rule.defaultConfiguration)) {
          const level = rule.defaultConfiguration.level;
          if (level !== undefined && !['none', 'note', 'warning', 'error'].includes(String(level))) {
            push(issues, `${rulePath}.defaultConfiguration.level`, `invalid level: ${String(level)}`);
          }
        }
        if (isRecord(rule.properties)) {
          const sev = rule.properties['security-severity'];
          if (sev !== undefined) {
            if (typeof sev !== 'string' || !/^\d+(\.\d+)?$/.test(sev)) {
              push(
                issues,
                `${rulePath}.properties["security-severity"]`,
                'GitHub requires numeric string 0.0–10.0 (not qualitative labels)'
              );
            } else {
              const n = Number(sev);
              if (n < 0 || n > 10) {
                push(
                  issues,
                  `${rulePath}.properties["security-severity"]`,
                  'security-severity must be between 0.0 and 10.0'
                );
              }
            }
          }
        }
      });
    }

    if (!Array.isArray(run.results)) {
      push(issues, `${runPath}.results`, 'results must be an array');
      return;
    }

    run.results.forEach((result, resultIndex) => {
      const resultPath = `${runPath}.results[${resultIndex}]`;
      if (!isRecord(result)) {
        push(issues, resultPath, 'result must be an object');
        return;
      }
      if (typeof result.ruleId !== 'string' || !result.ruleId) {
        push(issues, `${resultPath}.ruleId`, 'ruleId is required');
      }
      if (!isRecord(result.message) || typeof result.message.text !== 'string') {
        push(issues, `${resultPath}.message.text`, 'message.text is required');
      }
      if (
        result.level !== undefined &&
        !['none', 'note', 'warning', 'error'].includes(String(result.level))
      ) {
        push(issues, `${resultPath}.level`, `invalid level: ${String(result.level)}`);
      }
      if (!Array.isArray(result.locations) || result.locations.length < 1) {
        push(issues, `${resultPath}.locations`, 'at least one location is required');
      } else {
        result.locations.forEach((loc, locIndex) => {
          const locPath = `${resultPath}.locations[${locIndex}]`;
          if (!isRecord(loc) || !isRecord(loc.physicalLocation)) {
            push(issues, `${locPath}.physicalLocation`, 'physicalLocation is required');
            return;
          }
          const artifact = loc.physicalLocation.artifactLocation;
          if (!isRecord(artifact) || typeof artifact.uri !== 'string' || !artifact.uri) {
            push(issues, `${locPath}.physicalLocation.artifactLocation.uri`, 'uri is required');
          }
        });
      }
      if (isRecord(result.properties)) {
        const sev = result.properties['security-severity'];
        if (sev !== undefined && (typeof sev !== 'string' || !/^\d+(\.\d+)?$/.test(sev))) {
          push(
            issues,
            `${resultPath}.properties["security-severity"]`,
            'must be numeric string for GitHub Code Scanning'
          );
        }
      }
    });

    if (Array.isArray(run.invocations)) {
      run.invocations.forEach((inv, invIndex) => {
        if (!isRecord(inv)) {
          push(issues, `${runPath}.invocations[${invIndex}]`, 'invocation must be an object');
          return;
        }
        if (typeof inv.executionSuccessful !== 'boolean') {
          push(
            issues,
            `${runPath}.invocations[${invIndex}].executionSuccessful`,
            'executionSuccessful boolean is required when invocations present'
          );
        }
      });
    }
  });

  return { ok: issues.length === 0, issues };
}

export function assertValidSarifDocument(doc: unknown): void {
  const result = validateSarifDocument(doc);
  if (!result.ok) {
    const detail = result.issues
      .slice(0, 8)
      .map((i) => `${i.path}: ${i.message}`)
      .join('; ');
    throw new Error(`SARIF 2.1.0 validation failed (${result.issues.length} issue(s)): ${detail}`);
  }
}

export const SARIF_2_1_SCHEMA_URI = SARIF_SCHEMA_URI;
