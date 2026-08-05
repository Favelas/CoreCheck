import * as http from 'node:http';
import { URL } from 'node:url';

import { ControlPlaneStore } from './store.js';
import {
  LicenseValidationRequest,
  UsageTelemetryEvent
} from '../types/license.js';

type Json = Record<string, unknown> | unknown[];

/**
 * Router HTTP del SaaS Control Panel (validación, cuota, revoke, telemetría).
 * Compatible con el SaaSApiClient del CLI.
 */
export class ControlPlaneRouter {
  constructor(private readonly store: ControlPlaneStore = new ControlPlaneStore()) {}

  public getStore(): ControlPlaneStore {
    return this.store;
  }

  public async handle(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    try {
      const host = req.headers.host ?? 'localhost';
      const url = new URL(req.url ?? '/', `http://${host}`);
      const method = (req.method ?? 'GET').toUpperCase();
      const pathname = url.pathname.replace(/\/+$/, '') || '/';

      if (method === 'GET' && pathname === '/health') {
        return this.json(res, 200, { ok: true, service: 'corecheck-control-plane' });
      }

      if (method === 'POST' && pathname === '/v1/licenses/validate') {
        const body = (await this.readJson(req)) as unknown as LicenseValidationRequest;
        try {
          const license = this.store.validate(body);
          return this.json(res, 200, license);
        } catch (error) {
          const code = (error as { code?: string }).code ?? 'INVALID_KEY';
          return this.json(res, 401, { ok: false, code, message: (error as Error).message });
        }
      }

      if (method === 'POST' && pathname === '/v1/telemetry/usage') {
        const body = (await this.readJson(req)) as unknown as UsageTelemetryEvent;
        this.store.pushTelemetry(body);
        return this.json(res, 202, { ok: true });
      }

      if (method === 'GET' && pathname === '/v1/telemetry/usage') {
        return this.json(res, 200, { events: this.store.listTelemetry() });
      }

      const statusMatch = pathname.match(/^\/v1\/accounts\/([^/]+)\/status$/);
      if (method === 'GET' && statusMatch) {
        try {
          return this.json(res, 200, this.store.accountStatus(decodeURIComponent(statusMatch[1])));
        } catch {
          return this.json(res, 404, { code: 'ACCOUNT_NOT_FOUND' });
        }
      }

      const renewMatch = pathname.match(/^\/v1\/accounts\/([^/]+)\/quota\/renew$/);
      if (method === 'POST' && renewMatch) {
        try {
          await this.readJson(req);
          return this.json(
            res,
            200,
            this.store.renewQuota(decodeURIComponent(renewMatch[1]))
          );
        } catch {
          return this.json(res, 404, { code: 'ACCOUNT_NOT_FOUND' });
        }
      }

      const revokeMatch = pathname.match(/^\/v1\/accounts\/([^/]+)\/revoke$/);
      if (method === 'POST' && revokeMatch) {
        try {
          const body = (await this.readJson(req)) as { reason?: string };
          return this.json(
            res,
            200,
            this.store.revoke(decodeURIComponent(revokeMatch[1]), body.reason)
          );
        } catch {
          return this.json(res, 404, { code: 'ACCOUNT_NOT_FOUND' });
        }
      }

      this.json(res, 404, { ok: false, code: 'NOT_FOUND', path: pathname });
    } catch (error) {
      this.json(res, 500, {
        ok: false,
        code: 'INTERNAL',
        message: (error as Error).message
      });
    }
  }

  private async readJson(req: http.IncomingMessage): Promise<Json> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    if (chunks.length === 0) {
      return {};
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf-8')) as Json;
  }

  private json(res: http.ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(payload)
    });
    res.end(payload);
  }
}

export function createControlPlaneServer(
  port = 8787,
  store?: ControlPlaneStore
): http.Server {
  const router = new ControlPlaneRouter(store);
  const server = http.createServer((req, res) => {
    void router.handle(req, res);
  });
  server.listen(port, () => {
    console.log(`[ControlPlane] listening on http://127.0.0.1:${port}`);
  });
  return server;
}
