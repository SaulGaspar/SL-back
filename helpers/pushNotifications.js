const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';

async function sendOrderStatusNotification(db, { userId, orderId, pedidoRef, status }) {
  const [rows] = await db.execute(
    'SELECT token FROM push_tokens WHERE user_id = ? AND active = 1',
    [userId],
  );
  if (!rows.length) return { sent: 0 };

  const messages = rows.map(({ token }) => ({
    to: token,
    sound: 'default',
    channelId: 'orders',
    title: 'Tu pedido cambió de estado',
    body: `El pedido #${pedidoRef || orderId} ahora está ${String(status).replace('_', ' ')}.`,
    data: { orderId: pedidoRef || orderId },
    priority: 'high',
  }));

  const response = await fetch(EXPO_PUSH_URL, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(messages),
  });
  if (!response.ok) throw new Error(`Expo Push respondió ${response.status}`);
  return { sent: messages.length, result: await response.json() };
}

module.exports = { sendOrderStatusNotification };
