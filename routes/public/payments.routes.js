const crypto = require('crypto');
const express = require('express');
const { Preference } = require('mercadopago');

const { getDB } = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');
const {
  getMercadoPagoClient,
  getPayment,
  getApprovedPaymentForUser,
  validateWebhookSignature,
  hashCartItems,
} = require('../../helpers/mercadoPago');
const { createPaidOrder } = require('../../helpers/createPaidOrder');

const router = express.Router();
const SHIPPING_COST = 75;
const FREE_SHIPPING_FROM = 1500;

function cleanBaseUrl(value, fallback) {
  return String(value || fallback).replace(/\/+$/, '');
}

function normalizeItems(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 50) {
    const error = new Error('El carrito no contiene productos válidos');
    error.statusCode = 400;
    throw error;
  }

  const merged = new Map();
  for (const item of rawItems) {
    const productId = Number(item.product_id);
    const quantity = Number(item.cantidad);
    if (!Number.isInteger(productId) || productId <= 0) {
      const error = new Error('Hay un producto inválido en el carrito');
      error.statusCode = 400;
      throw error;
    }
    if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 20) {
      const error = new Error('La cantidad solicitada no es válida');
      error.statusCode = 400;
      throw error;
    }
    merged.set(productId, (merged.get(productId) || 0) + quantity);
  }

  return [...merged.entries()].map(([product_id, cantidad]) => ({
    product_id,
    cantidad,
  }));
}

router.post('/preference', authMiddleware, async (req, res) => {
  try {
    const items = normalizeItems(req.body.items);
    const addressId = Number(req.body.direccion_id);

    if (!Number.isInteger(addressId) || addressId <= 0) {
      return res.status(400).json({ error: 'Selecciona una dirección de envío válida' });
    }

    const db = await getDB();
    const [[address]] = await db.execute(
      'SELECT id FROM direcciones WHERE id = ? AND usuario_id = ?',
      [addressId, req.user.id]
    );
    if (!address) {
      return res.status(400).json({ error: 'La dirección seleccionada no es válida' });
    }

    const placeholders = items.map(() => '?').join(',');
    const [products] = await db.execute(
      `SELECT id, nombre, descripcion, precio
       FROM products
       WHERE id IN (${placeholders}) AND activo = 1`,
      items.map((item) => item.product_id)
    );

    if (products.length !== items.length) {
      return res.status(400).json({
        error: 'Uno o más productos ya no se encuentran disponibles',
      });
    }

    const [stockRows] = await db.execute(
      `SELECT i.product_id, MAX(i.stock) AS max_stock
       FROM inventory i
       JOIN branches b ON b.id = i.branch_id AND b.activo = 1
       WHERE i.product_id IN (${placeholders})
       GROUP BY i.product_id`,
      items.map((item) => item.product_id)
    );
    const stockMap = new Map(
      stockRows.map((row) => [Number(row.product_id), Number(row.max_stock)])
    );
    const unavailable = items.find(
      (item) => (stockMap.get(item.product_id) || 0) < item.cantidad
    );
    if (unavailable) {
      const product = products.find(
        (candidate) => Number(candidate.id) === unavailable.product_id
      );
      return res.status(409).json({
        error: `Stock insuficiente para "${product?.nombre || 'el producto seleccionado'}"`,
      });
    }

    const productMap = new Map(products.map((product) => [Number(product.id), product]));
    const preferenceItems = items.map((item) => {
      const product = productMap.get(item.product_id);
      return {
        id: String(product.id),
        title: String(product.nombre).slice(0, 120),
        description: String(product.descripcion || 'Producto SportLike').slice(0, 250),
        currency_id: 'MXN',
        quantity: item.cantidad,
        unit_price: Number(product.precio),
      };
    });

    const subtotal = preferenceItems.reduce(
      (sum, item) => sum + item.unit_price * item.quantity,
      0
    );
    const shipping = subtotal >= FREE_SHIPPING_FROM ? 0 : SHIPPING_COST;

    if (shipping > 0) {
      preferenceItems.push({
        id: 'shipping',
        title: 'Envío SportLike',
        description: 'Entrega del pedido',
        currency_id: 'MXN',
        quantity: 1,
        unit_price: shipping,
      });
    }

    const [[user]] = await db.execute(
      'SELECT correo, nombre, apellidoP FROM users WHERE id = ?',
      [req.user.id]
    );

    const frontendUrl = cleanBaseUrl(
      process.env.FRONTEND_URL,
      'https://sportlikeapps.netlify.app'
    );
    const backendUrl = cleanBaseUrl(
      process.env.BACKEND_PUBLIC_URL,
      'https://sl-back.vercel.app'
    );
    const externalReference = `sportlike:${req.user.id}:${crypto.randomUUID()}`;

    const preference = new Preference(getMercadoPagoClient());
    const result = await preference.create({
      body: {
        items: preferenceItems,
        payer: user?.correo
          ? {
              email: user.correo,
              name: user.nombre || undefined,
              surname: user.apellidoP || undefined,
            }
          : undefined,
        external_reference: externalReference,
        metadata: {
          user_id: String(req.user.id),
          address_id: String(addressId),
          cart_hash: hashCartItems(items),
          cart_items_json: JSON.stringify(items),
        },
        back_urls: {
          success: `${frontendUrl}/pago?mp_result=success`,
          failure: `${frontendUrl}/pago?mp_result=failure`,
          pending: `${frontendUrl}/pago?mp_result=pending`,
        },
        auto_return: 'approved',
        notification_url: `${backendUrl}/api/payments/webhook`,
        statement_descriptor: 'SPORTLIKE',
      },
      requestOptions: {
        idempotencyKey: externalReference,
      },
    });

    const useSandbox = String(process.env.MP_USE_SANDBOX).toLowerCase() === 'true';
    res.status(201).json({
      preference_id: result.id,
      checkout_url: useSandbox ? result.sandbox_init_point : result.init_point,
      subtotal,
      shipping,
      total: subtotal + shipping,
    });
  } catch (error) {
    console.error('Error creando preferencia Mercado Pago:', error.message);
    res.status(error.statusCode || 500).json({
      error: error.statusCode
        ? error.message
        : 'No se pudo iniciar el pago con Mercado Pago',
    });
  }
});

router.post('/complete', authMiddleware, async (req, res) => {
  try {
    const payment = await getApprovedPaymentForUser(
      req.body.payment_id,
      req.user.id
    );
    const result = await createPaidOrder({
      payment,
      userId: req.user.id,
      addressId: req.body.direccion_id,
      items: req.body.items,
    });
    res.json(result);
  } catch (error) {
    console.error('Error completando pedido pagado:', error.message);
    res.status(error.statusCode || 500).json({
      error: error.message || 'No se pudo completar el pedido pagado',
      payment_status: error.paymentStatus,
    });
  }
});

router.get('/payment/:paymentId', authMiddleware, async (req, res) => {
  try {
    const payment = await getPayment(req.params.paymentId);
    const ownerId =
      payment?.metadata?.user_id ||
      String(payment?.external_reference || '').split(':')[1];

    if (String(ownerId) !== String(req.user.id)) {
      return res.status(403).json({ error: 'El pago no pertenece al usuario' });
    }

    res.json({
      id: payment.id,
      status: payment.status,
      status_detail: payment.status_detail,
      transaction_amount: payment.transaction_amount,
      external_reference: payment.external_reference,
    });
  } catch (error) {
    console.error('Error consultando pago Mercado Pago:', error.message);
    res.status(error.statusCode || 500).json({
      error: error.statusCode ? error.message : 'No se pudo consultar el pago',
    });
  }
});

router.post('/webhook', async (req, res) => {
  try {
    validateWebhookSignature(req);
    const type = req.query.type || req.body?.type;
    const paymentId = req.query['data.id'] || req.body?.data?.id;

    if (type === 'payment' && paymentId) {
      const payment = await getPayment(paymentId);
      console.log(
        `Mercado Pago webhook | pago ${payment.id} | estado ${payment.status} | referencia ${payment.external_reference || '-'}`
      );

      if (payment.status === 'approved') {
        const userId = Number(payment?.metadata?.user_id);
        const addressId = Number(payment?.metadata?.address_id);
        let items = [];
        try {
          items = JSON.parse(payment?.metadata?.cart_items_json || '[]');
        } catch {
          items = [];
        }

        if (userId > 0 && addressId > 0 && items.length > 0) {
          await createPaidOrder({ payment, userId, addressId, items });
        } else {
          console.warn(`Pago ${payment.id} aprobado sin metadata suficiente para crear pedido`);
        }
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('Webhook Mercado Pago rechazado:', error.message);
    res.status(error.statusCode || 500).json({ error: error.message });
  }
});

module.exports = router;
