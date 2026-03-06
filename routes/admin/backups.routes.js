const express = require('express');
const router  = express.Router();
const { createClient } = require('@supabase/supabase-js');

const { getDB }         = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// ── Supabase client (service role = acceso total a Storage) ──────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const BUCKET = 'backup';

// ── Tablas a respaldar (en orden por dependencias FK) ────────────────────────
const TABLAS = [
  'users',
  'branches',
  'products',
  'inventory',
  'orders',
  'order_items',
  'Token',
];

// ── Helper: genera el SQL completo de una tabla ──────────────────────────────
async function generarSQLTabla(db, tabla) {
  let sql = `-- ============================================================\n`;
  sql    += `-- Tabla: ${tabla}\n`;
  sql    += `-- ============================================================\n\n`;

  // Obtener estructura
  try {
    const [cols] = await db.execute(`SHOW CREATE TABLE \`${tabla}\``);
    if (cols.length > 0) {
      const createSQL = cols[0]['Create Table'] || cols[0][`Create Table`];
      sql += `DROP TABLE IF EXISTS \`${tabla}\`;\n`;
      sql += `${createSQL};\n\n`;
    }
  } catch (e) {
    sql += `-- No se pudo obtener estructura de ${tabla}: ${e.message}\n\n`;
    return sql;
  }

  // Obtener datos
  try {
    const [rows] = await db.execute(`SELECT * FROM \`${tabla}\``);

    if (rows.length === 0) {
      sql += `-- Sin registros en ${tabla}\n\n`;
      return sql;
    }

    // Insertar en lotes de 100
    const columns = Object.keys(rows[0]).map(c => `\`${c}\``).join(', ');
    const lotes   = [];

    for (let i = 0; i < rows.length; i += 100) {
      lotes.push(rows.slice(i, i + 100));
    }

    for (const lote of lotes) {
      const values = lote.map(row => {
        const vals = Object.values(row).map(val => {
          if (val === null)              return 'NULL';
          if (typeof val === 'number')   return val;
          if (typeof val === 'boolean')  return val ? 1 : 0;
          if (val instanceof Date)       return `'${val.toISOString().slice(0,19).replace('T',' ')}'`;
          const escaped = String(val).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          return `'${escaped}'`;
        });
        return `(${vals.join(', ')})`;
      }).join(',\n  ');

      sql += `INSERT INTO \`${tabla}\` (${columns}) VALUES\n  ${values};\n\n`;
    }
  } catch (e) {
    sql += `-- No se pudieron exportar datos de ${tabla}: ${e.message}\n\n`;
  }

  return sql;
}

// ================================
// ➕ POST /api/admin/backups/generate
// ================================

router.post('/generate', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db   = await getDB();
    const ahora = new Date();
    const fecha = ahora.toISOString().slice(0,19).replace(/:/g,'-').replace('T','_');
    const nombre = `backup_${fecha}.sql`;

    // Cabecera del archivo SQL
    let sqlCompleto = `-- ============================================================\n`;
    sqlCompleto    += `-- SportLike Database Backup\n`;
    sqlCompleto    += `-- Generado: ${ahora.toLocaleString('es-MX')}\n`;
    sqlCompleto    += `-- Generado por: ${req.user.usuario}\n`;
    sqlCompleto    += `-- Tablas: ${TABLAS.join(', ')}\n`;
    sqlCompleto    += `-- ============================================================\n\n`;
    sqlCompleto    += `SET FOREIGN_KEY_CHECKS = 0;\n\n`;

    // Generar SQL de cada tabla
    for (const tabla of TABLAS) {
      sqlCompleto += await generarSQLTabla(db, tabla);
    }

    sqlCompleto += `SET FOREIGN_KEY_CHECKS = 1;\n`;
    sqlCompleto += `\n-- Fin del backup\n`;

    // Convertir a Buffer
    const buffer      = Buffer.from(sqlCompleto, 'utf-8');
    const tamanioBytes = buffer.length;

    // Subir a Supabase Storage
    const storagePath = `${fecha}/${nombre}`;

    const { error: uploadError } = await supabase.storage
      .from(BUCKET)
      .upload(storagePath, buffer, {
        contentType: 'text/plain',
        upsert: false,
      });

    if (uploadError) {
      console.error('Error subiendo a Supabase Storage:', uploadError);
      return res.status(500).json({ error: 'Error guardando el backup en Storage' });
    }

    // Guardar metadata en tabla backups de Aiven
    await db.execute(
      `INSERT INTO backups (nombre, tablas_incluidas, tamanio_bytes, storage_path, creado_por, creado_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [nombre, TABLAS.join(','), tamanioBytes, storagePath, req.user.usuario]
    );

    console.log(`✅ Backup generado: ${nombre} (${(tamanioBytes/1024).toFixed(1)} KB) por ${req.user.usuario}`);

    res.json({
      message: 'Backup generado correctamente',
      nombre,
      tamanio_bytes: tamanioBytes,
      storage_path: storagePath,
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
    console.error('Error obteniendo backups:', err);
    res.status(500).json({ error: 'Error obteniendo lista de backups' });
  }
});

// ================================
// 📥 GET /api/admin/backups/:id/download
// ================================

router.get('/:id/download', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      'SELECT * FROM backups WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Backup no encontrado' });
    }

    const backup = rows[0];

    // Generar URL firmada (válida 60 segundos)
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(backup.storage_path, 60);

    if (error) {
      console.error('Error generando URL firmada:', error);
      return res.status(500).json({ error: 'Error generando enlace de descarga' });
    }

    console.log(`📥 Descarga de backup: ${backup.nombre} por ${req.user.usuario}`);

    res.json({ url: data.signedUrl, nombre: backup.nombre });

  } catch (err) {
    console.error('Error en descarga de backup:', err);
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

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Backup no encontrado' });
    }

    const backup = rows[0];

    // Eliminar de Supabase Storage
    const { error } = await supabase.storage
      .from(BUCKET)
      .remove([backup.storage_path]);

    if (error) {
      console.warn('Advertencia eliminando de Storage:', error.message);
      // Continuar aunque falle Storage para limpiar la BD
    }

    // Eliminar de la tabla
    await db.execute('DELETE FROM backups WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Backup eliminado: ${backup.nombre} por ${req.user.usuario}`);
    res.json({ message: 'Backup eliminado correctamente' });

  } catch (err) {
    console.error('Error eliminando backup:', err);
    res.status(500).json({ error: 'Error eliminando backup' });
  }
});

module.exports = router;
