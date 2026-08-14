import type { ApiKeyRepository } from './apiKeys.repository';

let repository: ApiKeyRepository | undefined;

export function setApiKeyRepository(next: ApiKeyRepository): void {
  repository = next;
}

export function getApiKeyRepository(): ApiKeyRepository {
  if (!repository) {
    throw new Error(
      'ApiKeyRepository no inicializado. createApp() debe registrarlo.'
    );
  }
  return repository;
}
