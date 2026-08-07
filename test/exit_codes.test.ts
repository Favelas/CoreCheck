import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CoreCheckError,
  ExitCode,
  classifyError,
  exitCodeLabel
} from '../src/utils/exit_codes.ts';

describe('exit_codes taxonomy', () => {
  it('maps CoreCheckError kinds to stable codes 0-4 (excl. PASS)', () => {
    assert.equal(new CoreCheckError('c', 'CONFIG').exitCode, ExitCode.CONFIG);
    assert.equal(new CoreCheckError('n', 'NETWORK').exitCode, ExitCode.NETWORK);
    assert.equal(new CoreCheckError('e', 'ENGINE').exitCode, ExitCode.ENGINE);
    assert.equal(new CoreCheckError('l', 'LICENSE').exitCode, ExitCode.CONFIG);
    assert.equal(ExitCode.PASS, 0);
    assert.equal(ExitCode.GATE_FAIL, 1);
    assert.equal(ExitCode.CONFIG, 2);
    assert.equal(ExitCode.NETWORK, 3);
    assert.equal(ExitCode.ENGINE, 4);
  });

  it('classifyError never collapses engine/network into GATE_FAIL', () => {
    assert.equal(classifyError(new Error('ENOTFOUND example.com')), ExitCode.NETWORK);
    assert.equal(classifyError(new Error('net::ERR_CONNECTION_REFUSED')), ExitCode.NETWORK);
    assert.equal(
      classifyError(new Error('JavaScript heap out of memory')),
      ExitCode.ENGINE
    );
    assert.equal(
      classifyError(new Error('Failed to launch chromium')),
      ExitCode.ENGINE
    );
    assert.equal(
      classifyError(new Error('URL inválida en --url')),
      ExitCode.CONFIG
    );
    assert.equal(classifyError(new Error('something unexpected')), ExitCode.ENGINE);
    assert.notEqual(classifyError(new Error('ENOTFOUND')), ExitCode.GATE_FAIL);
  });

  it('exitCodeLabel covers the public taxonomy', () => {
    assert.equal(exitCodeLabel(ExitCode.PASS), 'PASS');
    assert.equal(exitCodeLabel(ExitCode.GATE_FAIL), 'GATE_FAIL');
    assert.equal(exitCodeLabel(ExitCode.CONFIG), 'CONFIG');
    assert.equal(exitCodeLabel(ExitCode.NETWORK), 'NETWORK');
    assert.equal(exitCodeLabel(ExitCode.ENGINE), 'ENGINE');
  });
});
