-- Ejecutar una sola vez en la BD seleccionada, antes de publicar el backend.
-- Conserva las filas existentes. No crea ni elimina tablas.
-- NULL significa que el pedido histórico no registró esa opción.
ALTER TABLE order_items
  ADD COLUMN talla VARCHAR(80) NULL AFTER product_id,
  ADD COLUMN color VARCHAR(80) NULL AFTER talla;
