import * as path from 'path';

import { OutputFormat } from '../types/audit.js';

/**
 * Contrato público CLI CoreCheck v1.0 (estable para consumidores CI/CD).
 *
 * Precedencia de formatos:
 * 1. Si `-f/--formats` viene de CLI → lista canónica; los toggles booleanos se unen (union).
 * 2. Si `-f/--formats` es default y hay toggles (`--html|--json|--sarif|--markdown|--pdf`)
 *    → los toggles definen el set completo.
 * 3. Si no hay toggles → default `json,html,sarif`.
 * 4. `--output-pdf` implica incluir `pdf`.
 *
 * Precedencia de salida:
 * - `-o/--output-dir` y `--out` son mutuamente excluyentes si ambos vienen de CLI
 *   y resuelven a directorios distintos.
 * - `--out <dir>` ≡ `--output-dir <dir>`.
 * - `--out <file>` ⇒ directorio padre + layout flat + basename preferido del artefacto.
 */

export const DEFAULT_FORMATS_CSV = 'json,html,sarif';

export const VALID_OUTPUT_FORMATS = new Set<OutputFormat>([
  'json',
  'sarif',
  'html',
  'markdown',
  'pdf'
]);

export const CANONICAL_ARTIFACT_NAMES = {
  html: 'report.html',
  json: 'findings.json',
  sarif: 'results.sarif',
  markdown: 'report.md',
  pdf: 'executive-report.pdf',
  dashboard: 'interactive-dashboard.html'
} as const;

export type OptionValueSource = string | undefined;

export interface FormatToggleFlags {
  html?: boolean;
  json?: boolean;
  sarif?: boolean;
  markdown?: boolean;
  pdf?: boolean;
}

export interface ResolveFormatsInput {
  formatsCsv: string;
  formatsSource: OptionValueSource;
  toggles: FormatToggleFlags;
  /** Si se pide un PDF con nombre explícito, se implica el formato pdf. */
  outputPdf?: string;
}

export interface ResolveOutputInput {
  outputDir: string;
  outputDirSource: OptionValueSource;
  out?: string;
  outSource: OptionValueSource;
  flatOutput: boolean;
  flatOutputSource: OptionValueSource;
  outputPdf?: string;
}

export interface ResolvedArtifactLayout {
  baseOutputDir: string;
  flatOutput: boolean;
  htmlFileName: string;
  pdfFileName: string;
}

function uniqueFormats(formats: OutputFormat[]): OutputFormat[] {
  return [...new Set(formats)];
}

export function parseFormatsCsv(raw: string): OutputFormat[] {
  const formats = raw
    .split(',')
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean) as OutputFormat[];

  if (formats.length === 0) {
    throw new Error(
      'Debe indicar al menos un formato en --formats (json,sarif,html,markdown,pdf).'
    );
  }

  const invalid = formats.filter((f) => !VALID_OUTPUT_FORMATS.has(f));
  if (invalid.length > 0) {
    throw new Error(
      `Formato(s) inválido(s): ${invalid.join(', ')}. Válidos: ${[...VALID_OUTPUT_FORMATS].join(', ')}.`
    );
  }

  return uniqueFormats(formats);
}

function collectToggleFormats(toggles: FormatToggleFlags): OutputFormat[] {
  const selected: OutputFormat[] = [];
  if (toggles.html) selected.push('html');
  if (toggles.json) selected.push('json');
  if (toggles.sarif) selected.push('sarif');
  if (toggles.markdown) selected.push('markdown');
  if (toggles.pdf) selected.push('pdf');
  return selected;
}

/**
 * Resuelve el set final de formatos según el contrato v1.0.
 */
export function resolveOutputFormats(input: ResolveFormatsInput): OutputFormat[] {
  const toggles = collectToggleFormats(input.toggles);
  let formats =
    input.formatsSource === 'cli'
      ? parseFormatsCsv(input.formatsCsv)
      : toggles.length > 0
        ? uniqueFormats(toggles)
        : parseFormatsCsv(input.formatsCsv);

  if (input.formatsSource === 'cli' && toggles.length > 0) {
    formats = uniqueFormats([...formats, ...toggles]);
  }

  if (input.outputPdf && !formats.includes('pdf')) {
    formats = [...formats, 'pdf'];
  }

  return formats;
}

function extensionImpliesArtifact(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.html', '.htm', '.json', '.sarif', '.md', '.markdown', '.pdf'].includes(ext);
}

/**
 * Resuelve directorio de salida, layout flat y nombres canónicos de artefacto.
 */
export function resolveArtifactLayout(input: ResolveOutputInput): ResolvedArtifactLayout {
  let baseOutputDir = path.resolve(input.outputDir);
  let flatOutput = input.flatOutput;
  let htmlFileName: string = CANONICAL_ARTIFACT_NAMES.html;
  let pdfFileName = input.outputPdf
    ? path.basename(String(input.outputPdf))
    : CANONICAL_ARTIFACT_NAMES.pdf;

  if (input.out !== undefined && input.outSource === 'cli') {
    const outResolved = path.resolve(input.out);
    const outIsFile = extensionImpliesArtifact(input.out);

    if (outIsFile) {
      if (input.flatOutputSource === 'cli' && input.flatOutput === false) {
        throw new Error(
          'Conflicto de contrato CLI: `--out <archivo>` implica layout flat. ' +
            'Quite el flag que desactiva --flat-output, o pase un directorio a --out.'
        );
      }

      baseOutputDir = path.dirname(outResolved);
      flatOutput = true;

      const base = path.basename(outResolved);
      const ext = path.extname(base).toLowerCase();
      if (ext === '.html' || ext === '.htm') {
        htmlFileName = base;
      } else if (ext === '.pdf') {
        pdfFileName = base;
      }
    } else {
      baseOutputDir = outResolved;
    }

    if (
      input.outputDirSource === 'cli' &&
      path.resolve(input.outputDir) !== baseOutputDir
    ) {
      throw new Error(
        'Conflicto de contrato CLI: no combine `--out` y `--output-dir` con rutas distintas. ' +
          `Recibido --output-dir="${input.outputDir}" vs --out="${input.out}".`
      );
    }
  }

  return {
    baseOutputDir,
    flatOutput,
    htmlFileName,
    pdfFileName
  };
}
