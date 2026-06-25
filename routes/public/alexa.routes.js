const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');

const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://sl-back.vercel.app').replace(/\/$/, '');

const autenticarAlexa = (req, res, next) => {
  const key = req.headers['x-alexa-key'];
  const validKey = process.env.ALEXA_INTERNAL_KEY;
  if (!key || !validKey || key !== validKey) {
    console.warn(`Acceso no autorizado desde IP: ${req.ip}`);
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
};

router.use(autenticarAlexa);

const normalizar = (texto) =>
  String(texto || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();

const dividirLista = (texto) =>
  texto ? String(texto).split(',').map(t => t.trim()).filter(Boolean) : [];

const imagenPublica = (imagen) => {
  const value = String(imagen || '').trim();
  if (!value) return null;
  if (value.startsWith('https://')) return value;
  if (value.startsWith('http://')) return value.replace('http://', 'https://');
  if (value.startsWith('/')) return `${PUBLIC_BASE_URL}${value}`;
  return `${PUBLIC_BASE_URL}/${value.replace(/^\/+/, '')}`;
};

const mapearProducto = (r) => ({
  id: r.id,
  nombre: r.nombre,
  marca: r.marca || null,
  descripcion: r.descripcion || null,
  precio: r.precio,
  categoria: r.categoria,
  imagen: imagenPublica(r.imagen),
  imageUrl: imagenPublica(r.imagen),
  tallas: dividirLista(r.talla),
  colores: dividirLista(r.colores),
  activo: Number(r.activo) === 1,
  disponible: Number(r.activo) === 1,
  stock: Number(r.stock) || 0,
});

const SELECT_PRODUCTOS = `
  SELECT
    p.id, p.nombre, p.marca, p.descripcion, p.precio, p.categoria,
    COALESCE(
      (SELECT url FROM product_images WHERE product_id = p.id ORDER BY id ASC LIMIT 1),
      p.imagen
    ) as imagen,
    p.talla, p.colores, p.activo,
    COALESCE(SUM(i.stock), 0) AS stock
  FROM products p
  LEFT JOIN inventory i ON i.product_id = p.id
`;

const GROUP_PRODUCTOS = `
  GROUP BY p.id, p.nombre, p.marca, p.descripcion, p.precio, p.categoria,
    p.imagen, p.talla, p.colores, p.activo
`;

router.get('/products/all', async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit || '100', 10) || 100, 1), 200);
    const db = await getDB();
    const [rows] = await db.execute(`
      ${SELECT_PRODUCTOS}
      WHERE p.activo = 1
      ${GROUP_PRODUCTOS}
      ORDER BY p.id DESC
      LIMIT ${limit}
    `);
    res.json({ total: rows.length, products: rows.map(mapearProducto) });
  } catch (err) {
    console.error('GET /products/all:', err.message);
    res.status(500).json({ error: 'Error interno del servidor', detail: err.message });
  }
});

router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Se requiere ?name=categoría' });

    const db = await getDB();
    const [rows] = await db.execute(`
      ${SELECT_PRODUCTOS}
      WHERE p.activo = 1
        AND LOWER(TRIM(p.categoria)) = LOWER(TRIM(?))
      ${GROUP_PRODUCTOS}
      ORDER BY RAND()
      LIMIT 6
    `, [name]);

    res.json({ category: name, total: rows.length, products: rows.map(mapearProducto) });
  } catch (err) {
    console.error('GET /products/category:', err.message);
    res.status(500).json({ error: 'Error interno del servidor', detail: err.message });
  }
});

router.get('/product/details', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Se requiere ?name=producto' });

    const db = await getDB();
    
    // Primero intenta búsqueda EXACTA o muy similar
    let [rows] = await db.execute(`
      ${SELECT_PRODUCTOS}
      WHERE p.activo = 1
        AND LOWER(TRIM(p.nombre)) = LOWER(TRIM(?))
      ${GROUP_PRODUCTOS}
    `, [name]);

    // Si no hay resultado exacto, intenta búsqueda parcial
    if (!rows.length) {
      const terminos = normalizar(name).split(/\s+/).filter(t => t.length > 1);
      const whereTerminos = terminos.map(() => 'LOWER(p.nombre) LIKE LOWER(?)').join(' OR ');
      const params = terminos.map(t => `%${t}%`);

      [rows] = await db.execute(`
        ${SELECT_PRODUCTOS}
        WHERE p.activo = 1
          ${whereTerminos ? `AND (${whereTerminos})` : ''}
        ${GROUP_PRODUCTOS}
        ORDER BY CHAR_LENGTH(p.nombre) ASC
        LIMIT 1
      `, params);
    }

    if (!rows.length) return res.json({ found: false });
    res.json({ found: true, product: mapearProducto(rows[0]) });
  } catch (err) {
    console.error('GET /product/details:', err.message);
    res.status(500).json({ error: 'Error interno del servidor', detail: err.message });
  }
});

router.get('/stock', async (req, res) => {
  try {
    const { product, size, color, branch_id } = req.query;
    if (!product) return res.status(400).json({ error: 'Se requiere ?product=nombre' });

    const branchJoinFilter = branch_id ? 'AND i.branch_id = ?' : '';
    const params = branch_id ? [branch_id, `%${product}%`] : [`%${product}%`];

    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT
        p.id, p.nombre, p.marca, p.descripcion, p.precio, p.categoria,
        COALESCE(
          (SELECT url FROM product_images WHERE product_id = p.id ORDER BY id ASC LIMIT 1),
          p.imagen
        ) as imagen,
        p.talla, p.colores, p.activo,
        COALESCE(SUM(i.stock), 0) AS stock
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id ${branchJoinFilter}
      WHERE p.activo = 1
        AND LOWER(p.nombre) LIKE LOWER(?)
      ${GROUP_PRODUCTOS}
    `, params);

    const productos = rows.map(mapearProducto).filter(p => {
      const okSize = !size || p.tallas.map(normalizar).includes(normalizar(size));
      const okColor = !color || p.colores.map(normalizar).includes(normalizar(color));
      return okSize && okColor;
    });

    const colors = [...new Set(productos.flatMap(p => p.colores))];
    const sizes = [...new Set(productos.flatMap(p => p.tallas))];
    const prices = productos.map(p => Number(p.precio)).filter(Number.isFinite);
    const totalStock = productos.reduce((sum, p) => sum + (Number(p.stock) || 0), 0);
    const activeProduct = productos.some(p => p.activo);

    res.json({
      available: activeProduct,
      totalStock,
      colors,
      sizes,
      priceFrom: prices.length ? Math.min(...prices) : null,
    });
  } catch (err) {
    console.error('GET /stock:', err.message);
    res.status(500).json({ error: 'Error consultando stock', detail: err.message });
  }
});

router.get('/categories', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT p.categoria, COUNT(DISTINCT p.id) AS total
      FROM products p
      WHERE p.activo = 1
        AND p.categoria IS NOT NULL
      GROUP BY p.categoria
      ORDER BY p.categoria ASC
    `);
    res.json({
      total: rows.length,
      categories: rows.map(r => ({ name: r.categoria, count: r.total })),
    });
  } catch (err) {
    console.error('GET /categories:', err.message);
    res.status(500).json({ error: 'Error obteniendo categorías', detail: err.message });
  }
});

router.get('/branches', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, direccion, telefono, activo
      FROM branches
      WHERE activo = 1
      ORDER BY nombre ASC
    `);
    res.json({
      total: rows.length,
      branches: rows.map(b => ({
        name: b.nombre,
        address: b.direccion,
        phone: b.telefono || null,
        schedule: 'Lunes a sábado de 9:00 AM a 8:00 PM',
      })),
    });
  } catch (err) {
    console.error('GET /branches:', err.message);
    res.status(500).json({ error: 'Error obteniendo sucursales' });
  }
});

router.get('/promotions', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, descuento, fecha_inicio, fecha_fin, activo
      FROM promotions
      WHERE activo = 1
        AND fecha_inicio <= CURDATE()
        AND fecha_fin >= CURDATE()
      ORDER BY fecha_fin ASC
      LIMIT 5
    `);
    res.json({ 
      total: rows.length, 
      promotions: rows.map(r => ({
        name: r.nombre,
        discount: r.descuento,
        startDate: r.fecha_inicio,
        endDate: r.fecha_fin,
      }))
    });
  } catch (err) {
    console.error('GET /promotions:', err.message);
    res.status(500).json({ error: 'Error obteniendo promociones' });
  }
});

module.exports = router;
