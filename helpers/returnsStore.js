const { getDB } = require('../config/db');

let tableReady;

function ensureReturnsTable() {
  if (!tableReady) {
    tableReady = (async () => {
      const db = await getDB();
      try {
        await db.execute('SELECT 1 FROM return_requests LIMIT 1');
        return;
      } catch (error) {
        if (error.code !== 'ER_NO_SUCH_TABLE' && error.errno !== 1146) {
          throw error;
        }
      }

      await db.execute(`
        CREATE TABLE IF NOT EXISTS return_requests (
          id INT NOT NULL AUTO_INCREMENT,
          order_id INT NOT NULL,
          user_id INT NOT NULL,
          reason ENUM('damaged', 'wrong_item', 'size', 'quality', 'other') NOT NULL,
          details TEXT NOT NULL,
          evidence_images JSON NULL,
          requested_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
          status ENUM('requested', 'reviewing', 'approved', 'rejected', 'refunded')
            NOT NULL DEFAULT 'requested',
          admin_notes TEXT NULL,
          reviewed_by INT NULL,
          reviewed_at DATETIME NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          UNIQUE KEY uq_return_order (order_id),
          INDEX idx_return_user (user_id),
          INDEX idx_return_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);
    })().catch((error) => {
      tableReady = null;
      throw error;
    });
  }
  return tableReady;
}

module.exports = { ensureReturnsTable };
