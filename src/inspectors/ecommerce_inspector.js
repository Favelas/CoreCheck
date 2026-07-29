// src/inspectors/ecommerce_inspector.js
async function inspectEcommerce(page) {
  return await page.evaluate(() => {
    const priceElements = Array.from(document.querySelectorAll('[class*="price"], [id*="price"], .amount, [data-price]'));
    const buyButtons = Array.from(document.querySelectorAll('button, a, input[type="submit"]')).filter(el => {
      const txt = (el.innerText || el.value || '').toLowerCase();
      return txt.includes('add to cart') || txt.includes('añadir') || txt.includes('comprar') || txt.includes('checkout') || txt.includes('cart');
    });

    if (priceElements.length === 0 && buyButtons.length === 0) {
      return { hasEcommerce: false, alerts: [], detections: [] };
    }

    const alerts = [];
    if (priceElements.length > 0 && buyButtons.length === 0) {
      alerts.push(`⚠️ E-COMMERCE: Hay precios visibles pero no se detectaron botones de compra claros`);
    }

    return {
      hasEcommerce: true,
      priceCount: priceElements.length,
      buyButtonCount: buyButtons.length,
      alerts,
      detections: [`🛒 E-Commerce (${priceElements.length} precios, ${buyButtons.length} CTAs)`]
    };
  });
}

module.exports = { inspectEcommerce };