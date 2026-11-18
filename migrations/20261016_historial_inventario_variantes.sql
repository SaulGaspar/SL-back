-- PREPARACIÓN: respaldo de la BD y prueba en una copia antes de producción.
-- No ejecutar automáticamente. No elimina ni reparte las existencias actuales.
CREATE TABLE IF NOT EXISTS historial_admin (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 usuario_id INT NULL,
 usuario VARCHAR(80) NOT NULL,
 accion VARCHAR(80) NOT NULL,
 entidad VARCHAR(50) NOT NULL,
 entidad_id BIGINT NULL,
 antes JSON NULL,
 despues JSON NULL,
 creado_en DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_historial_fecha (creado_en,id),
 INDEX idx_historial_entidad (entidad,entidad_id),
 INDEX idx_historial_usuario (usuario_id,creado_en)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inventario_variantes (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 inventario_id INT NOT NULL,
 talla VARCHAR(80) NOT NULL DEFAULT 'Único',
 color VARCHAR(80) NOT NULL DEFAULT 'Único',
 stock INT NOT NULL DEFAULT 0,
 UNIQUE KEY uq_inventario_variante (inventario_id,talla,color),
 CONSTRAINT fk_variante_inventario FOREIGN KEY (inventario_id) REFERENCES inventory(id) ON DELETE RESTRICT,
 CONSTRAINT chk_variante_stock CHECK (stock >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Después de revisar esta migración, activar en el backend:
-- SPORTLIKE_AUDIT_ENABLED=true
-- SPORTLIKE_VARIANTS_ENABLED=true
-- Configurar el desglose REAL de cada producto/sucursal en el panel.
-- Los registros sin desglose NO se venderán como variantes hasta configurarlos.
