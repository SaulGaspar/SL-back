// routes/admin/backups.js
const express    = require('express');
const router     = express.Router();
const cron       = require('node-cron');
const { createClient } = require('@supabase/supabase-js');

const { getDB }                        = require('../../config/db');
const { authMiddleware, adminOnly }    = require('../../middlewares/auth');
const { TABLAS, generarSQLTabla }      = require('../../utils/backupHelper');

// ── Supabase client ──────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const BUCKET = 'backup';

// ── Jobs en memoria (id -> cron task) ────────────────────────
const activeJobs = {};

// ── Helper: ejecutar un backup completo ─────────────────────
async function ejecutarBackup(db, tipo = 'manual', autor = 'sistema') {
  const ahora  = new Date();
  const fecha  = ahora.toISOString().slice(0, 19).replace(/:/g, '-').replace('T', '_');
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

// ── Helper: limpiar backups automáticos > 7 días ─────────────
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
}

// ── Helper: convertir schedule a expresión cron ──────────────
function toCronExpr(schedule) {
  const [h, m] = (schedule.hora || '02:00').split(':').map(Number);
  switch (schedule.frecuencia) {
    case 'diario':  return `${m} ${h} * * *`;
    case 'semanal': return `${m} ${h} * * ${schedule.dia_semana ?? 0}`;
    case 'mensual': return `${m} ${h} 1 * *`;
    case 'horas':   return `0 */${schedule.cada_horas ?? 6} * * *`;
    default:        return `${m} ${h} * * *`;
  }
}

// ── Iniciar todos los schedules activos al arrancar ──────────
async function iniciarSchedules() {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM backup_schedules WHERE activo = 1`
    ).catch(() => [[]]);

    for (const sch of rows) {
      const expr = toCronExpr(sch);
      if (!cron.validate(expr)) continue;

      activeJobs[sch.id] = cron.schedule(expr, async () => {
        try {
          const db2    = await getDB();
          const result = await ejecutarBackup(db2, sch.frecuencia, 'sistema');
          await db2.execute(
            `UPDATE backup_schedules SET ultima_ejecucion = NOW() WHERE id = ?`, [sch.id]
          );
          console.log(`✅ [Schedule ${sch.id}] ${result.nombre}`);
        } catch (err) {
          console.error(`❌ [Schedule ${sch.id}]`, err.message);
        }
      }, { timezone: 'America/Mexico_City' });

      console.log(`📅 Schedule ${sch.id} activado: ${expr} (${sch.frecuencia})`);
    }
  } catch (err) {
    console.error('Error iniciando schedules:', err.message);
  }
}

iniciarSchedules();

// ================================
// 🤖 GET /api/admin/backups/cron
// Llamado por Vercel Cron Jobs
// ================================
router.get('/cron', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  const ahora  = new Date();
  const dia    = ahora.getUTCDate();
  const diaSem = ahora.getUTCDay();

  let tipo = 'diario';
  if (dia === 1)         tipo = 'mensual';
  else if (diaSem === 0) tipo = 'semanal';

  try {
    const db     = await getDB();
    const result = await ejecutarBackup(db, tipo, 'sistema');
    await limpiarBackupsAntiguos(db);
    return res.json({ ok: true, tipo, nombre: result.nombre, tamanio_bytes: result.tamanioBytes });
  } catch (err) {
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
    res.json({
      message:       'Backup generado correctamente',
      nombre:        result.nombre,
      tamanio_bytes: result.tamanioBytes,
      storage_path:  result.storagePath,
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
    if (!rows.length) return res.status(404).json({ error: 'Backup no encontrado' });

    const { data, error } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(rows[0].storage_path, 60);

    if (error) return res.status(500).json({ error: 'Error generando enlace de descarga' });
    res.json({ url: data.signedUrl, nombre: rows[0].nombre });
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
    if (!rows.length) return res.status(404).json({ error: 'Backup no encontrado' });

    await supabase.storage.from(BUCKET).remove([rows[0].storage_path]);
    await db.execute('DELETE FROM backups WHERE id = ?', [req.params.id]);
    res.json({ message: 'Backup eliminado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error eliminando backup' });
  }
});

// ================================
// 📋 GET /api/admin/backups/schedules
// ================================
router.get('/schedules', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM backup_schedules ORDER BY creado_at DESC`
    ).catch(() => [[]]);

    res.json(rows.map(s => ({
      ...s,
      running:   !!activeJobs[s.id],
      cron_expr: toCronExpr(s),
    })));
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo schedules' });
  }
});

// ================================
// ➕ POST /api/admin/backups/schedules
// Body: { frecuencia, hora, dia_semana?, cada_horas?, nombre? }
// ================================
router.post('/schedules', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const {
      frecuencia, hora = '02:00',
      dia_semana = null, cada_horas = null,
      nombre = 'Respaldo automático',
    } = req.body;

    if (!frecuencia) return res.status(400).json({ error: 'frecuencia es requerida' });

    const [result] = await db.execute(
      `INSERT INTO backup_schedules (nombre, frecuencia, hora, dia_semana, cada_horas, activo, creado_por)
       VALUES (?, ?, ?, ?, ?, 1, ?)`,
      [nombre, frecuencia, hora, dia_semana, cada_horas, req.user.usuario]
    );

    const newId    = result.insertId;
    const schedule = { id: newId, frecuencia, hora, dia_semana, cada_horas };
    const expr     = toCronExpr(schedule);

    if (cron.validate(expr)) {
      activeJobs[newId] = cron.schedule(expr, async () => {
        try {
          const db2 = await getDB();
          const r   = await ejecutarBackup(db2, frecuencia, 'sistema');
          await db2.execute(`UPDATE backup_schedules SET ultima_ejecucion = NOW() WHERE id = ?`, [newId]);
          console.log(`✅ [Schedule ${newId}] ${r.nombre}`);
        } catch (err) {
          console.error(`❌ [Schedule ${newId}]`, err.message);
        }
      }, { timezone: 'America/Mexico_City' });
    }

    res.json({ message: 'Schedule creado y activado', id: newId, cron_expr: expr });
  } catch (err) {
    console.error('Error creando schedule:', err);
    res.status(500).json({ error: 'Error creando schedule' });
  }
});

// ================================
// ⏸️ PATCH /api/admin/backups/schedules/:id/toggle
// ================================
router.patch('/schedules/:id/toggle', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db  = await getDB();
    const id  = parseInt(req.params.id);
    const [rows] = await db.execute(`SELECT * FROM backup_schedules WHERE id = ?`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Schedule no encontrado' });

    const sch    = rows[0];
    const newVal = sch.activo ? 0 : 1;

    await db.execute(`UPDATE backup_schedules SET activo = ? WHERE id = ?`, [newVal, id]);

    if (newVal === 0) {
      if (activeJobs[id]) { activeJobs[id].stop(); delete activeJobs[id]; }
    } else {
      const expr = toCronExpr(sch);
      if (cron.validate(expr)) {
        activeJobs[id] = cron.schedule(expr, async () => {
          try {
            const db2 = await getDB();
            const r   = await ejecutarBackup(db2, sch.frecuencia, 'sistema');
            await db2.execute(`UPDATE backup_schedules SET ultima_ejecucion = NOW() WHERE id = ?`, [id]);
            console.log(`✅ [Schedule ${id}] ${r.nombre}`);
          } catch (err) { console.error(`❌ [Schedule ${id}]`, err.message); }
        }, { timezone: 'America/Mexico_City' });
      }
    }

    res.json({ message: newVal ? 'Schedule activado' : 'Schedule pausado', activo: newVal });
  } catch (err) {
    console.error('Error en toggle schedule:', err);
    res.status(500).json({ error: 'Error actualizando schedule' });
  }
});

// ================================
// ▶️ POST /api/admin/backups/schedules/:id/run
// ================================
router.post('/schedules/:id/run', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db     = await getDB();
    const [rows] = await db.execute(`SELECT * FROM backup_schedules WHERE id = ?`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Schedule no encontrado' });

    const sch    = rows[0];
    const result = await ejecutarBackup(db, sch.frecuencia, req.user.usuario);
    await db.execute(`UPDATE backup_schedules SET ultima_ejecucion = NOW() WHERE id = ?`, [sch.id]);

    res.json({ message: 'Backup ejecutado', nombre: result.nombre, tamanio_bytes: result.tamanioBytes });
  } catch (err) {
    console.error('Error en run manual:', err);
    res.status(500).json({ error: 'Error ejecutando backup manual' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/backups/schedules/:id
// ================================
router.delete('/schedules/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db  = await getDB();
    const id  = parseInt(req.params.id);
    const [rows] = await db.execute(`SELECT * FROM backup_schedules WHERE id = ?`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Schedule no encontrado' });

    if (activeJobs[id]) { activeJobs[id].stop(); delete activeJobs[id]; }
    await db.execute(`DELETE FROM backup_schedules WHERE id = ?`, [id]);

    res.json({ message: 'Schedule eliminado' });
  } catch (err) {
    console.error('Error eliminando schedule:', err);
    res.status(500).json({ error: 'Error eliminando schedule' });
  }
});

module.exports = router;