import { Page } from 'playwright';
import * as path from 'path';
import * as fs from 'fs';

export interface MetaIssue {
  type: 'EXPOSED_GENERATOR' | 'MISSING_SECURITY_HEADER';
  severity: 'LOW';
  message: string;
}

export class VisualMetaInspector {
  constructor(private page: Page) {}

  /**
   * Toma una captura de pantalla completa del estado actual y la guarda en la carpeta del cliente
   */
  async captureScreenshot(outputDir: string, filename: string): Promise<string> {
    const screenshotsDir = path.join(outputDir, 'screenshots');
    if (!fs.existsSync(screenshotsDir)) {
      fs.mkdirSync(screenshotsDir, { recursive: true });
    }

    const screenshotPath = path.join(screenshotsDir, `${filename}.png`);
    await this.page.screenshot({ path: screenshotPath, fullPage: true });
    return screenshotPath;
  }

  /**
   * Examina meta-etiquetas para detectar versiones expuestas del CMS o tecnología
   */
  async inspectMetadata(): Promise<MetaIssue[]> {
    const issues: MetaIssue[] = [];

    try {
      const generator = await this.page.$eval(
        'meta[name="generator"]',
        (el) => el.getAttribute('content')
      ).catch(() => null);

      if (generator) {
        issues.push({
          type: 'EXPOSED_GENERATOR',
          severity: 'LOW',
          message: `El HTML expone la tecnología o versión en <meta name="generator">: '${generator}'`,
        });
      }
    } catch {
      // No hay meta generator
    }

    return issues;
  }
}