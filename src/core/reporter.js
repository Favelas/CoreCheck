const fs = require('fs');
const path = require('path');

function generateDashboardHTML(auditResults, runTimestamp, baseUrl, reportsDir) {
  const htmlPath = path.join(reportsDir, `audit_dashboard_${runTimestamp}.html`);

  const totalRoutes = auditResults.length;
  const passedRoutes = auditResults.filter(r => r.passed).length;
  const failedRoutes = totalRoutes - passedRoutes;
  const healthScore = Math.round((passedRoutes / totalRoutes) * 100) || 0;

  let totalAlerts = 0;
  auditResults.forEach(r => { totalAlerts += (r.alerts ? r.alerts.length : 0); });

  const htmlContent = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CoreCheck Audit Dashboard — ${baseUrl}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
  </style>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen pb-12">

  <!-- Top Bar Header -->
  <header class="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="bg-indigo-600 p-2 rounded-lg font-black text-xl tracking-wider">CC</div>
        <div>
          <h1 class="font-bold text-lg leading-none">CoreCheck Audit Engine</h1>
          <p class="text-xs text-slate-400 mt-1">Executive Quality & Security Report</p>
        </div>
      </div>
      <div class="text-right">
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
          Target: ${baseUrl}
        </span>
        <p class="text-xs text-slate-500 mt-1">Run: ${runTimestamp}</p>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-6 mt-8">

    <!-- KPI Summary Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
      <div class="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
        <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Health Score</p>
        <p class="text-3xl font-extrabold mt-2 ${healthScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}">${healthScore}%</p>
        <p class="text-xs text-slate-500 mt-1">${passedRoutes} de ${totalRoutes} rutas aprobadas</p>
      </div>

      <div class="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
        <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Rutas Auditadas</p>
        <p class="text-3xl font-extrabold mt-2 text-white">${totalRoutes}</p>
        <p class="text-xs text-slate-500 mt-1">Single Page App & Endpoints</p>
      </div>

      <div class="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
        <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Hallazgos / Alertas</p>
        <p class="text-3xl font-extrabold mt-2 ${totalAlerts === 0 ? 'text-emerald-400' : 'text-rose-400'}">${totalAlerts}</p>
        <p class="text-xs text-slate-500 mt-1">Requieren atención o remediación</p>
      </div>

      <div class="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
        <p class="text-xs font-medium text-slate-400 uppercase tracking-wider">Estado de Auditoría</p>
        <p class="text-xl font-bold mt-2 ${failedRoutes === 0 ? 'text-emerald-400' : 'text-rose-400'}">
          ${failedRoutes === 0 ? '✅ APROBADO' : '⚠️ REVISIÓN NECESARIA'}
        </p>
        <p class="text-xs text-slate-500 mt-1">Conformidad de OWASP & UX</p>
      </div>
    </div>

    <!-- Detailed Route Results -->
    <div class="bg-slate-800/40 border border-slate-700/50 rounded-xl overflow-hidden">
      <div class="px-6 py-4 border-b border-slate-700/50 flex justify-between items-center">
        <h2 class="font-semibold text-white">Desglose de Auditoría por Ruta</h2>
      </div>

      <div class="divide-y divide-slate-700/50">
        ${auditResults.map((item, idx) => `
          <div class="p-6 hover:bg-slate-800/20 transition-colors">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
              <div>
                <div class="flex items-center space-x-3">
                  <span class="font-mono text-sm font-semibold text-indigo-400 bg-indigo-950/50 px-2 py-1 rounded border border-indigo-800/40">
                    ${item.route}
                  </span>
                  <span class="text-xs text-slate-400">${item.title}</span>
                </div>
              </div>
              <div class="flex items-center space-x-4">
                <span class="text-xs text-slate-400 font-mono">⏱️ ${item.loadTimeMs}ms</span>
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${item.passed ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'}">
                  ${item.passed ? 'PASSED' : 'ACTION REQUIRED'}
                </span>
              </div>
            </div>

            <!-- Hallazgos -->
            ${item.alerts && item.alerts.length > 0 ? `
              <div class="mt-3 bg-rose-950/20 border border-rose-900/30 rounded-lg p-4 mb-4">
                <p class="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-2">Hallazgos Detectados (${item.alerts.length})</p>
                <ul class="space-y-1 text-sm text-rose-200">
                  ${item.alerts.map(a => `<li class="flex items-start"><span class="mr-2">•</span><span>${a}</span></li>`).join('')}
                </ul>
              </div>
            ` : `
              <div class="mt-3 bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-3 mb-4 text-xs text-emerald-300">
                ✓ No se detectaron vulnerabilidades ni errores de rendimiento en esta ruta.
              </div>
            `}

            <!-- Capturas Evidencia -->
            <div class="flex items-center space-x-4 text-xs text-slate-400 pt-2 border-t border-slate-700/30">
              <span>Evidencias de renderizado:</span>
              ${item.deskFile ? `<a href="screenshots/${item.deskFile}" target="_blank" class="text-indigo-400 hover:underline">🖥️ Desktop Spec</a>` : ''}
              ${item.mobFile ? `<a href="screenshots/${item.mobFile}" target="_blank" class="text-indigo-400 hover:underline">📱 Mobile Spec</a>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  </main>
</body>
</html>`;

  fs.writeFileSync(htmlPath, htmlContent, 'utf-8');
  console.log(`📊 Dashboard HTML generado: ${htmlPath}`);
}

module.exports = { generateDashboardHTML };