/**
 * Entry point — solo bootstrap HTTP.
 * La composición de middlewares/rutas vive en src/app.ts.
 */
import { createApp } from './src/app';

const PORT = Number(process.env['PORT']) || 3000;
const app = createApp();

app.listen(PORT, () => {
  console.log(`[CoreCheck API] Servidor ejecutándose en http://localhost:${PORT}`);
});
