// routes/admin/backups.js
const express = require('express');
const router  = express.Router();
const { createClient } = require('@supabase/supabase-js');

const { getDB }          = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { TABLAS, generarSQLTabla }   = require('../../utils/backupHelper');

// ── Supabase client ──────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const BUCKET = 'backup';

// ── Helper interno para ejecutar el backup ───────────────────────────────────
async function ejecutarBackup(db, tipo = 'manual', autor = 'sistema') {
  const ahora = new Date();
  const fecha = ahora.toISOString().slice(0,19).replace(/:/g,'-').replace('T','_');
  const nombre = tipo === 'manual'
    ? `backup_${fecha}.sql`
    : `backup_auto_${tipo}_${fecha}.sql`;

  let sqlCompleto  = `-- ============================================================\n`;
  sqlCompleto     += `-- SportLike Database Backup (${tipo.toUpperCase()})\n`;
  sqlCompleto     += `-- Generado: ${ahora.toLocaleString('es-MX')}\n`;
  sqlCompleto     += `-- Generado por: ${autor}\n`;
  sqlCompleto     += `-- Tablas: ${TABLAS.join(', ')}\n`;
  sqlCompleto     += `-- ============================================================\n\n`;
  sqlCompleto     += `SET FOREIGN_KEY_CHECKS = 0;\n\n`;

  for (const tabla of TABLAS) {
    sqlCompleto += await generarSQLTabla(db, tabla);
  }

  sqlCompleto += `SET FOREIGN_KEY_CHECKS = 1;\n\n-- Fin del backup\n`;

  const buffer       = Buffer.from(sqlCompleto, 'utf-8');
  const tamanioBytes = buffer.length;
  const storagePath  = tipo === 'manual'
    ? `${fecha}/${nombre}`
    : `auto/${tipo}/${fecha}/${nombre}`;

  const { error: uploadError } = await supabase.storage
    .from(BUCKET)
    .upload(storagePath, buffer, { contentType: 'text/plain', upsert: false });

  if (uploadError) throw uploadError;

  await db.execute(
    `INSERT INTO backups (nombre, tablas_incluidas, tamanio_bytes, storage_path, creado_por, creado_at)
     VALUES (?, ?, ?, ?, ?, NOW())`,
    [nombre, TABLAS.join(','), tamanioBytes, storagePath, autor]
  );

  return { nombre, tamanioBytes, storagePath };
}

// ── Helper: limpiar backups automáticos con más de 7 días ───────────────────
async function limpiarBackupsAntiguos(db) {
  const DIAS = 7;
  const [viejos] = await db.execute(
    `SELECT id, storage_path, nombre FROM backups
     WHERE creado_por = 'sistema' AND creado_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
    [DIAS]
  );

  for (const b of viejos) {
    await supabase.storage.from(BUCKET).remove([b.storage_path]);
    await db.execute('DELETE FROM backups WHERE id = ?', [b.id]);
    console.log(`🧹 Backup antiguo eliminado: ${b.nombre}`);
  }

  if (viejos.length > 0) {
    console.log(`🧹 Total eliminados: ${viejos.length} backup(s) automático(s) con más de ${DIAS} días`);
  } else {
    console.log(`🧹 Sin backups automáticos antiguos que limpiar`);
  }
}

// ================================
// 🤖 GET /api/admin/backups/cron
// Llamado exclusivamente por Vercel Cron Jobs
// Horario actual: 6:30 AM UTC = 12:30 AM México (prueba)
// Horario final:  8:00 AM UTC =  2:00 AM México (producción)
// ================================
router.get('/cron', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    console.warn('⛔ Intento no autorizado al endpoint /cron');
    return res.status(401).json({ error: 'No autorizado' });
  }

  const ahora  = new Date();
  const dia    = ahora.getUTCDate();
  const diaSem = ahora.getUTCDay(); // 0 = domingo

  // Un solo cron diario decide el tipo según la fecha
  let tipo = 'diario';
  if (dia === 1)         tipo = 'mensual';
  else if (diaSem === 0) tipo = 'semanal';

  console.log(`\n🤖 Cron ejecutado — tipo: ${tipo} | ${ahora.toISOString()}`);

  try {
    const db     = await getDB();
    const result = await ejecutarBackup(db, tipo, 'sistema');

    console.log(`✅ Backup automático: ${result.nombre} (${(result.tamanioBytes/1024).toFixed(1)} KB)`);

    // Limpiar backups automáticos con más de 7 días
    await limpiarBackupsAntiguos(db);

    return res.json({
      ok           : true,
      tipo,
      nombre       : result.nombre,
      tamanio_bytes: result.tamanioBytes,
    });

  } catch (err) {
    console.error('❌ Error en cron de backup:', err.message);
    return res.status(500).json({ error: 'Error ejecutando backup automático', detalle: err.message });
  }
});

// ================================
// ➕ POST /api/admin/backups/generate
// ================================
router.post('/generate', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db     = await getDB();
    const result = await ejecutarBackup(db, 'manual', req.user.usuario);

    console.log(`✅ Backup manual: ${result.nombre} por ${req.user.usuario}`);

    res.json({
      message      : 'Backup generado correctamente',
      nombre       : result.nombre,
      tamanio_bytes: result.tamanioBytes,
      storage_path : result.storagePath,
    });

  } catch (err) {
    console.error('Error generando backup:', err);
    res.status(500).json({ error: 'Error generando el backup', detalle: err.message });
  }
});

// ================================
// 📋 GET /api/admin/backups
// ================================
router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT id, nombre, tablas_incluidas, tamanio_bytes, storage_path, creado_por, creado_at
       FROM backups ORDER BY creado_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo lista de backups' });
  }
});

// ================================
// 📥 GET /api/admin/backups/:id/download
// ================================
router.get('/:id/download', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM backups WHERE id = ?', [req.params.id]);

    if (rows.length === 0) return res.status(404).json({ error: 'Backup no encontrado' });

    const backup = rows[0];
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(backup.storage_path, 60);

    if (error) return res.status(500).json({ error: 'Error generando enlace de descarga' });

    console.log(`📥 Descarga: ${backup.nombre} por ${req.user.usuario}`);
    res.json({ url: data.signedUrl, nombre: backup.nombre });

  } catch (err) {
    res.status(500).json({ error: 'Error procesando descarga' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/backups/:id
// ================================
router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT * FROM backups WHERE id = ?', [req.params.id]);

    if (rows.length === 0) return res.status(404).json({ error: 'Backup no encontrado' });

    const backup = rows[0];

    await supabase.storage.from(BUCKET).remove([backup.storage_path]);
    await db.execute('DELETE FROM backups WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Backup eliminado: ${backup.nombre} por ${req.user.usuario}`);
    res.json({ message: 'Backup eliminado correctamente' });

  } catch (err) {
    res.status(500).json({ error: 'Error eliminando backup' });
  }
});

module.exports = router;