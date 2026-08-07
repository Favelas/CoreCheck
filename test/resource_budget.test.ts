import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ABSOLUTE_HARD_CAP,
  CI_SMALL_HARD_CAP,
  LOCAL_MODEST_HARD_CAP,
  chromiumLaunchArgsForBudget,
  clampConcurrency
} from '../src/utils/resource_budget.ts';

const GB = 1024 * 1024 * 1024;

describe('resource_budget.clampConcurrency', () => {
  it('caps CI runners to CI_SMALL_HARD_CAP even if requested higher', () => {
    const result = clampConcurrency({
      requestedConcurrency: 8,
      forceCiProfile: true,
      totalMemBytes: 7 * GB,
      freeMemBytes: 5 * GB
    });
    assert.equal(result.profile, 'ci-small');
    assert.equal(result.concurrency, CI_SMALL_HARD_CAP);
    assert.equal(result.capped, true);
    assert.ok(result.reason?.includes('capped'));
  });

  it('never raises concurrency above the request', () => {
    const result = clampConcurrency({
      requestedConcurrency: 1,
      forceCiProfile: true,
      totalMemBytes: 32 * GB,
      freeMemBytes: 28 * GB
    });
    assert.equal(result.concurrency, 1);
    assert.equal(result.capped, false);
  });

  it('applies modest local hard cap under 8GB total RAM', () => {
    const result = clampConcurrency({
      requestedConcurrency: 10,
      forceCiProfile: false,
      totalMemBytes: 7 * GB,
      freeMemBytes: 5 * GB
    });
    assert.equal(result.profile, 'local');
    assert.ok(result.concurrency <= LOCAL_MODEST_HARD_CAP);
    assert.equal(result.capped, true);
  });

  it('tightens further when free memory is critically low', () => {
    const result = clampConcurrency({
      requestedConcurrency: 4,
      forceCiProfile: false,
      totalMemBytes: 16 * GB,
      freeMemBytes: 1.6 * GB // barely above reserve → memCap ≈ 1
    });
    assert.equal(result.concurrency, 1);
    assert.equal(result.capped, true);
  });

  it('respects absolute hard cap on high-mem hosts', () => {
    const result = clampConcurrency({
      requestedConcurrency: 64,
      forceCiProfile: false,
      totalMemBytes: 64 * GB,
      freeMemBytes: 48 * GB
    });
    assert.equal(result.profile, 'high-mem');
    assert.equal(result.concurrency, ABSOLUTE_HARD_CAP);
    assert.equal(result.capped, true);
  });

  it('accounts for fuzzing overhead (stricter memCap)', () => {
    const base = clampConcurrency({
      requestedConcurrency: 4,
      activeFuzzing: false,
      forceCiProfile: false,
      totalMemBytes: 16 * GB,
      freeMemBytes: 4 * GB
    });
    const fuzz = clampConcurrency({
      requestedConcurrency: 4,
      activeFuzzing: true,
      forceCiProfile: false,
      totalMemBytes: 16 * GB,
      freeMemBytes: 4 * GB
    });
    assert.ok(fuzz.concurrency <= base.concurrency);
  });

  it('exposes Chromium flags safe for GHA /dev/shm', () => {
    const args = chromiumLaunchArgsForBudget();
    assert.ok(args.includes('--disable-dev-shm-usage'));
    assert.ok(args.includes('--no-sandbox'));
  });
});
