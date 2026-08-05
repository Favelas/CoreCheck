import { BrowserContext, Page } from 'playwright';

import { AuditAuthConfig } from '../types/audit.js';

export interface AuthSessionResult {
  authenticated: boolean;
  storageState?: Awaited<ReturnType<BrowserContext['storageState']>>;
  extraHTTPHeaders?: Record<string, string>;
}

/**
 * Automatiza sesión previa al crawling: headers Bearer y/o form-login
 * con captura de cookies + localStorage vía storageState de Playwright.
 */
export class AuthHandler {
  public async authenticate(
    context: BrowserContext,
    authConfig?: AuditAuthConfig,
    timeoutMs = 30000
  ): Promise<AuthSessionResult> {
    if (!authConfig) {
      return { authenticated: false };
    }

    const hasHeaders =
      !!authConfig.customHeaders && Object.keys(authConfig.customHeaders).length > 0;
    const hasFormLogin = !!(
      authConfig.loginUrl &&
      authConfig.username !== undefined &&
      authConfig.password !== undefined
    );

    if (!hasHeaders && !hasFormLogin) {
      return { authenticated: false };
    }

    const result: AuthSessionResult = { authenticated: false };

    if (hasHeaders && authConfig.customHeaders) {
      await context.setExtraHTTPHeaders(authConfig.customHeaders);
      result.extraHTTPHeaders = { ...authConfig.customHeaders };
      console.log(
        `[Auth] Inyectados ${Object.keys(authConfig.customHeaders).length} custom header(s)`
      );
    }

    if (hasFormLogin) {
      const page = await context.newPage();
      try {
        await this.performFormLogin(page, authConfig, timeoutMs);
        result.storageState = await context.storageState();
        result.authenticated = true;
        console.log(`[Auth] Sesión establecida vía form-login en ${authConfig.loginUrl}`);
      } catch (error) {
        console.error(`[Auth] Fallo en form-login: ${(error as Error).message}`);
        throw error;
      } finally {
        await page.close().catch(() => {});
      }
    } else if (hasHeaders) {
      result.authenticated = true;
    }

    return result;
  }

  private async performFormLogin(
    page: Page,
    authConfig: AuditAuthConfig,
    timeoutMs: number
  ): Promise<void> {
    const loginUrl = authConfig.loginUrl!;
    const username = authConfig.username!;
    const password = authConfig.password!;

    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });

    const userSelector = [
      'input[type="email"]',
      'input[name="username"]',
      'input[name="email"]',
      'input[name="user"]',
      'input[id="username"]',
      'input[id="email"]',
      'input[autocomplete="username"]',
      'input[type="text"]'
    ].join(', ');

    const passSelector = 'input[type="password"]';
    const submitSelector = [
      'button[type="submit"]',
      'input[type="submit"]',
      'button:has-text("Log in")',
      'button:has-text("Login")',
      'button:has-text("Sign in")',
      'button:has-text("Iniciar")'
    ].join(', ');

    const userField = page.locator(userSelector).first();
    const passField = page.locator(passSelector).first();

    await userField.waitFor({ state: 'visible', timeout: timeoutMs });
    await passField.waitFor({ state: 'visible', timeout: timeoutMs });

    await userField.fill(username, { timeout: timeoutMs });
    await passField.fill(password, { timeout: timeoutMs });

    const submit = page.locator(submitSelector).first();
    if (await submit.count()) {
      await Promise.all([
        page.waitForLoadState('domcontentloaded').catch(() => {}),
        submit.click({ timeout: timeoutMs })
      ]);
    } else {
      await passField.press('Enter');
      await page.waitForLoadState('domcontentloaded').catch(() => {});
    }

    // Dejar que la app persista cookies / tokens en storage.
    await page.waitForTimeout(800);

    const cookies = await page.context().cookies();
    const localKeys = await page
      .evaluate(() => Object.keys(window.localStorage || {}))
      .catch(() => [] as string[]);

    if (cookies.length === 0 && localKeys.length === 0) {
      console.warn(
        '[Auth] Login ejecutado pero no se detectaron cookies ni localStorage; la sesión puede ser inválida.'
      );
    }
  }
}
