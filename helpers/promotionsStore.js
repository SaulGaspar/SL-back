const { getDB } = require('../config/db');

let tableReady;

function ensurePromotionsTable() {
  if (!tableReady) {
    tableReady = (async () => {
      const db = await getDB();
      await db.execute(`
        CREATE TABLE IF NOT EXISTS promotions (
          id INT NOT NULL AUTO_INCREMENT,
          name VARCHAR(120) NOT NULL,
          description TEXT NOT NULL,
          discount_type ENUM('percentage', 'fixed') NOT NULL,
          discount_value DECIMAL(10,2) NOT NULL,
          applies_to ENUM('all', 'category', 'product') NOT NULL DEFAULT 'all',
          target VARCHAR(160) NULL,
          start_date DATE NOT NULL,
          end_date DATE NOT NULL,
          status ENUM('draft', 'active', 'inactive') NOT NULL DEFAULT 'draft',
          created_by INT NULL,
          notified_at DATETIME NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          INDEX idx_promotions_status_dates (status, start_date, end_date)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);
    })().catch((error) => {
      tableReady = null;
      throw error;
    });
  }

  return tableReady;
}

function normalizePromotion(input = {}) {
  return {
    name: String(input.name || '').trim(),
    description: String(input.description || '').trim(),
    discount_type: input.discount_type === 'fixed' ? 'fixed' : 'percentage',
    discount_value: Number(input.discount_value),
    applies_to: ['all', 'category', 'product'].includes(input.applies_to)
      ? input.applies_to
      : 'all',
    target: String(input.target || '').trim() || null,
    start_date: String(input.start_date || '').slice(0, 10),
    end_date: String(input.end_date || '').slice(0, 10),
    status: ['draft', 'active', 'inactive'].includes(input.status)
      ? input.status
      : 'draft',
  };
}

function validatePromotion(promotion) {
  const errors = [];

  if (promotion.name.length < 3 || promotion.name.length > 120) {
    errors.push('El nombre debe tener entre 3 y 120 caracteres');
  }
  if (promotion.description.length < 10 || promotion.description.length > 2000) {
    errors.push('La descripción debe tener entre 10 y 2000 caracteres');
  }
  if (!Number.isFinite(promotion.discount_value) || promotion.discount_value <= 0) {
    errors.push('El valor del descuento debe ser mayor que cero');
  }
  if (promotion.discount_type === 'percentage' && promotion.discount_value > 100) {
    errors.push('El descuento porcentual no puede superar el 100 %');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(promotion.start_date)) {
    errors.push('La fecha de inicio no es válida');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(promotion.end_date)) {
    errors.push('La fecha de finalización no es válida');
  }
  if (
    promotion.start_date &&
    promotion.end_date &&
    promotion.end_date < promotion.start_date
  ) {
    errors.push('La fecha de finalización debe ser igual o posterior a la fecha de inicio');
  }
  if (promotion.applies_to !== 'all' && !promotion.target) {
    errors.push('Indica el producto o la categoría a la que aplica la promoción');
  }

  return errors;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

module.exports = {
  ensurePromotionsTable,
  normalizePromotion,
  validatePromotion,
  escapeHtml,
};
