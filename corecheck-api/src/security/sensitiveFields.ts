/**
 * Campos prohibidos en ingest de reportes (SEC-API-01).
 * Comparación case-insensitive sobre el nombre de la propiedad.
 */
export const SENSITIVE_REPORT_FIELD_NAMES: ReadonlySet<string> = new Set(
  [
    'apikey',
    'api_key',
    'authorization',
    'password',
    'passwd',
    'cookie',
    'cookies',
    'token',
    'access_token',
    'refresh_token',
    'secret',
    'client_secret',
    'private_key',
    'privatekey'
  ].map((name) => name.toLowerCase())
);

/** Identidad del recurso: siempre asignada por el servidor. */
export const SERVER_OWNED_FIELD_NAMES: ReadonlySet<string> = new Set([
  'id',
  'createdat'
]);

export function isDeniedIngestField(fieldName: string): boolean {
  const normalized = fieldName.toLowerCase();
  return (
    SENSITIVE_REPORT_FIELD_NAMES.has(normalized) ||
    SERVER_OWNED_FIELD_NAMES.has(normalized)
  );
}
