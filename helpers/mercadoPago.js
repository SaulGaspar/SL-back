const {
  MercadoPagoConfig,
  Payment,
  WebhookSignatureValidator,
  InvalidWebhookSignatureError,
} = require('mercadopago');
const crypto = require('crypto');

let client = null;

function getMercadoPagoClient() {
  const accessToken = process.env.MP_ACCESS_TOKEN;
  if (!accessToken) {
    const error = new Error('Mercado Pago no está configurado');
    error.statusCode = 503;
    throw error;
  }

  if (!client) {
    client = new MercadoPagoConfig({
      accessToken,
      options: { timeout: 8000 },
    });
  }

  return client;
}

async function getPayment(paymentId) {
  if (!paymentId) {
    const error = new Error('Falta el identificador del pago');
    error.statusCode = 400;
    throw error;
  }

  const paymentClient = new Payment(getMercadoPagoClient());
  return paymentClient.get({ id: String(paymentId) });
}

function paymentOwnerId(payment) {
  const metadataUser = payment?.metadata?.user_id;
  if (metadataUser !== undefined && metadataUser !== null) {
    return String(metadataUser);
  }

  const reference = String(payment?.external_reference || '');
  const match = reference.match(/^sportlike:(\d+):/);
  return match ? match[1] : '';
}

function hashCartItems(items) {
  const normalized = (items || [])
    .map((item) => ({
      product_id: Number(item.product_id),
      cantidad: Number(item.cantidad),
    }))
    .sort((a, b) => a.product_id - b.product_id);

  return crypto
    .createHash('sha256')
    .update(JSON.stringify(normalized))
    .digest('hex');
}

async function getApprovedPaymentForUser(paymentId, userId) {
  const payment = await getPayment(paymentId);

  if (paymentOwnerId(payment) !== String(userId)) {
    const error = new Error('El pago no corresponde al usuario autenticado');
    error.statusCode = 403;
    throw error;
  }

  if (payment.status !== 'approved') {
    const error = new Error(
      payment.status === 'pending'
        ? 'El pago todavía está pendiente'
        : 'El pago no fue aprobado'
    );
    error.statusCode = 402;
    error.paymentStatus = payment.status;
    throw error;
  }

  return payment;
}

function validateWebhookSignature(req) {
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return true;

  const dataId = req.query['data.id'] || req.body?.data?.id;
  if (!dataId) {
    const error = new Error('Webhook sin data.id');
    error.statusCode = 400;
    throw error;
  }

  try {
    WebhookSignatureValidator.validate({
      xSignature: req.headers['x-signature'],
      xRequestId: req.headers['x-request-id'],
      dataId: String(dataId),
      secret,
    });
    return true;
  } catch (error) {
    if (error instanceof InvalidWebhookSignatureError) {
      const invalid = new Error('Firma de webhook inválida');
      invalid.statusCode = 401;
      throw invalid;
    }
    throw error;
  }
}

module.exports = {
  getMercadoPagoClient,
  getPayment,
  getApprovedPaymentForUser,
  validateWebhookSignature,
  hashCartItems,
};
