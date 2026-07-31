import fs from 'node:fs';
import path from 'node:path';

const MAX_SNIPPET_BYTES = 2048; // 2 KB Limit

export interface ProcessedEvidence {
  snippet?: string;
  artifactPath?: string;
}

export function sanitizeAndBudgetEvidence(
  findingId: string,
  rawSnippet?: string,
  artifactsDir: string = './audit-artifacts'
): ProcessedEvidence {
  if (!rawSnippet) return {};

  const snippetBuffer = Buffer.from(rawSnippet, 'utf-8');

  if (snippetBuffer.length <= MAX_SNIPPET_BYTES) {
    return { snippet: rawSnippet };
  }

  // Si excede 2KB, truncar snippet y volcar DOM completo a disco
  if (!fs.existsSync(artifactsDir)) {
    fs.mkdirSync(artifactsDir, { recursive: true });
  }

  const truncatedSnippet = snippetBuffer.subarray(0, MAX_SNIPPET_BYTES).toString('utf-8') + '\n... [TRUNCATED]';
  const fileName = `dom-evidence-${findingId}.html`;
  const fullPath = path.join(artifactsDir, fileName);

  fs.writeFileSync(fullPath, rawSnippet, 'utf-8');

  return {
    snippet: truncatedSnippet,
    artifactPath: fullPath
  };
}