# Historial y existencias por talla y color

## Cambios de base de datos propuestos

El archivo `20261016_historial_inventario_variantes.sql` crea dos tablas, sin eliminar tablas ni repartir automáticamente el stock:

- `historial_admin`: guarda actor, fecha, acción y datos anteriores/posteriores. No guarda contraseñas ni tokens. No tiene una clave foránea hacia usuarios, para conservar el registro aunque una cuenta se elimine después. La API solamente permite consultarlo a administradores activos. Esto no impide que alguien con acceso directo a MySQL altere la tabla; restringir ese acceso es responsabilidad de la administración de la BD.
- `inventario_variantes`: desglosa cada registro existente de `inventory` por talla/color. La combinación es única por inventario. `inventory.stock` permanece como total agregado, conservando compatibilidad con reportes. La relación usa RESTRICT para evitar borrados accidentales de un desglose.

No se ha ejecutado esta migración. Revisar primero los tipos y motor de `inventory.id` y probar sobre una copia respaldada. `IF NOT EXISTS` no comprueba que una tabla preexistente tenga las columnas esperadas.

## Orden de activación

1. Respaldar y probar en una copia. Revisar y ejecutar el SQL con una cuenta autorizada.
2. Desplegar el backend con `SPORTLIKE_AUDIT_ENABLED=true`. A partir de ese momento se registran las acciones nuevas; el pasado no se reconstruye.
3. Programar una ventana de configuración de inventario. Activar `SPORTLIKE_VARIANTS_ENABLED=true` y publicar el frontend compatible.
4. En **Inventario → Talla y color**, capturar el reparto físico de cada producto y sucursal. El primer desglose debe sumar exactamente el stock previo. Un registro sin desglose queda bloqueado para compras por variante, para no cobrar basándose en cantidades inventadas. Durante esta preparación no dejar abierta la venta general del sitio.
5. Probar una compra y una cancelación de prueba, transferencias y consultas del historial. Reabrir la venta al terminar todos los desgloses necesarios.

Las variables no se activan automáticamente. Sin ellas, el código mantiene el inventario anterior y muestra un aviso de activación pendiente en las pantallas nuevas. Tras comenzar a operar por variantes, no desactivar esa variable como método de rollback: los movimientos posteriores podrían desincronizar el detalle. Revertir requiere un plan y conciliación de existencias.

## Reglas operativas

- La talla y el color se toman de las opciones configuradas en el producto. Para retirar una combinación existente se deja en cero; no se borra su identidad histórica.
- Las ediciones de stock por talla/color recalculan el total de la sucursal dentro de una transacción. No se permite sobrescribir ese total desde Productos ni desde la importación general.
- Las transferencias restan y suman la misma talla/color entre sucursales. Antes de recibir una transferencia, el destino con stock previo debe tener su propio desglose.
- Una compra descuenta la combinación seleccionada. Una cancelación permitida la restituye una sola vez. No se efectúan reembolsos automáticos en Mercado Pago.
- Los pedidos históricos sin una combinación identificable requieren conciliación manual; no se inventa la talla/color al cancelar.
- Si falla la escritura del historial con la función activa, se revierte el cambio asociado.
- Si cambian existencias después de generar una preferencia de pago, la confirmación puede necesitar atención manual. Este cambio valida antes del cobro y al registrar el pedido, pero no introduce reservas temporales de inventario.

## Verificación local

`node scripts/check-inventory-audit.cjs` comprueba escenarios aislados con una BD simulada. No ejecuta transacciones reales en producción ni sustituye la prueba de migración en una copia MySQL.
