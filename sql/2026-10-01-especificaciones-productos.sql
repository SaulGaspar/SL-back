-- Especificaciones flexibles por producto (material, cuidados, composición, etc.)
-- Es una modificación aditiva: no elimina ni cambia información existente.
ALTER TABLE products
  ADD COLUMN especificaciones JSON NULL AFTER descripcion;
