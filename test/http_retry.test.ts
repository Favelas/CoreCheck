import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  computeBackoffDelayMs,
  isRetryableStatus,
  withExponentialBackoff
} from '../src/utils/http_retry.ts';

describe('http_retry exponential backoff', () => {
  it('recognizes 403/429/503 as retryable', () => {
    assert.equal(isRetryableStatus(403), true);
    assert.equal(isRetryableStatus(429), true);
    assert.equal(isRetryableStatus(503), true);
    assert.equal(isRetryableStatus(200), false);
    assert.equal(isRetryableStatus(404), false);
  });

  it('computeBackoffDelayMs grows with attempt and stays bounded', () => {
    const d1 = computeBackoffDelayMs(1, 100, 1000, () => 0);
    const d3 = computeBackoffDelayMs(3, 100, 1000, () => 0);
    assert.ok(d3 >= d1);
    assert.ok(d3 <= 1000);
  });

  it('retries retryable statuses then returns last value', async () => {
    const sleeps: number[] = [];
    let calls = 0;
    const outcome = await withExponentialBackoff(
      async () => {
        calls++;
        return { status: calls < 3 ? 429 : 200 };
      },
      (v) => v.status,
      {
        maxAttempts: 4,
        baseDelayMs: 10,
        maxDelayMs: 50,
        sleep: async (ms) => {
          sleeps.push(ms);
        },
        random: () => 0
      }
    );
    assert.equal(outcome.value.status, 200);
    assert.equal(outcome.attempts, 3);
    assert.ok(sleeps.length >= 2);
  });

  it('exhausts retries on persistent 403', async () => {
    const outcome = await withExponentialBackoff(
      async () => ({ status: 403 }),
      (v) => v.status,
      {
        maxAttempts: 3,
        baseDelayMs: 5,
        maxDelayMs: 20,
        sleep: async () => undefined,
        random: () => 0
      }
    );
    assert.equal(outcome.value.status, 403);
    assert.equal(outcome.attempts, 3);
  });
});
