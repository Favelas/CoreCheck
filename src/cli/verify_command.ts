import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';

import {
  verifyJsonReportAttestation,
  type VerifiableJsonReport
} from '../utils/attestation.js';
import { CoreCheckError, ExitCode, exitCodeLabel } from './exit_codes.js';

/**
 * Subcomando: `corecheck verify --report <file> [--key <secret>]`
 * Verifica integridad SHA-256 (+ autenticidad HMAC-SHA256 si aplica) de findings.json.
 */
export function registerVerifyCommand(program: Command): void {
  program
    .command('verify')
    .description(
      'Verifica integridad/autenticidad criptográfica de un findings.json (SHA-256 / HMAC-SHA256)'
    )
    .requiredOption(
      '--report <file>',
      'Ruta al informe JSON canónico (findings.json)'
    )
    .option(
      '--key <secret>',
      'Secret HMAC (alternativa: env CORECHECK_ATTESTATION_SECRET)'
    )
    .option(
      '--require-hmac',
      'Exige firma HMAC aunque el informe solo tenga SHA-256',
      false
    )
    .action((opts: { report: string; key?: string; requireHmac?: boolean }) => {
      try {
        const reportPath = path.resolve(String(opts.report));
        if (!fs.existsSync(reportPath)) {
          throw new CoreCheckError(
            `Informe no encontrado: ${reportPath}`,
            'CONFIG'
          );
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        } catch (err) {
          throw new CoreCheckError(
            `JSON corrupto en --report: ${(err as Error).message}`,
            'CONFIG'
          );
        }

        const report = parsed as VerifiableJsonReport;
        if (!report || typeof report !== 'object' || !report.target) {
          throw new CoreCheckError(
            'El archivo no parece un findings.json de CoreCheck (falta target).',
            'CONFIG'
          );
        }

        const result = verifyJsonReportAttestation(report, {
          hmacSecret: opts.key,
          requireHmac: Boolean(opts.requireHmac)
        });

        console.log(`[verify] report=${reportPath}`);
        console.log(`[verify] algorithm=${result.algorithm}`);
        console.log(`[verify] hashMatches=${result.hashMatches}`);
        console.log(
          `[verify] hmacVerified=${result.hmacVerified === null ? 'n/a' : result.hmacVerified}`
        );
        console.log(`[verify] expected=${result.expectedHash}`);
        console.log(`[verify] actual  =${result.actualHash}`);
        console.log(`[verify] ${result.message}`);

        if (!result.ok) {
          // Fallo de integridad/autenticidad → GATE_FAIL semántico (verificación fallida).
          console.error(`[verify] FAIL (${exitCodeLabel(ExitCode.GATE_FAIL)})`);
          process.exit(ExitCode.GATE_FAIL);
        }

        console.log(`[verify] OK (${exitCodeLabel(ExitCode.PASS)})`);
        process.exit(ExitCode.PASS);
      } catch (error) {
        if (error instanceof CoreCheckError) {
          console.error(`[verify] ${error.message}`);
          process.exit(error.exitCode);
        }
        console.error(`[verify] ${(error as Error).message}`);
        process.exit(ExitCode.ENGINE);
      }
    });
}
