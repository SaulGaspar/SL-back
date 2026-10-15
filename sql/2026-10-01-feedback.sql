-- Ejecutar una sola vez sobre la base de datos de SportLike.
-- Esta migración no modifica pedidos, productos ni usuarios existentes.

CREATE TABLE IF NOT EXISTS resenas_productos (
  id INT NOT NULL AUTO_INCREMENT,
  producto_id INT NOT NULL,
  usuario_id INT NOT NULL,
  calificacion TINYINT NOT NULL,
  comentario VARCHAR(500) NULL,
  estado ENUM('pendiente', 'publicada', 'rechazada') NOT NULL DEFAULT 'pendiente',
  notas_admin VARCHAR(500) NULL,
  creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_resena_producto_usuario (producto_id, usuario_id),
  KEY idx_resenas_publicas (producto_id, estado, creado_en),
  KEY idx_resenas_moderacion (estado, creado_en),
  CONSTRAINT fk_resenas_producto
    FOREIGN KEY (producto_id) REFERENCES products(id) ON DELETE CASCADE,
  CONSTRAINT fk_resenas_usuario
    FOREIGN KEY (usuario_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT chk_resenas_calificacion CHECK (calificacion BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS mensajes_contacto (
  id INT NOT NULL AUTO_INCREMENT,
  nombre VARCHAR(120) NOT NULL,
  correo VARCHAR(150) NOT NULL,
  mensaje VARCHAR(2000) NOT NULL,
  estado ENUM('nuevo', 'leido', 'cerrado') NOT NULL DEFAULT 'nuevo',
  creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_mensajes_contacto_estado (estado, creado_en)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
