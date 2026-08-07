/** Re-export público CLI → canónico en utils (evita dependencia core→cli). */
export {
  ExitCode,
  CoreCheckError,
  classifyError,
  exitCodeLabel,
  type ExitCodeValue,
  type CoreCheckErrorKind
} from '../utils/exit_codes.js';
