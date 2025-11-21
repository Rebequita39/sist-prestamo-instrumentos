// ===== Dependencias =====
const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
require('dotenv').config();

// ===== Conexión a la DB =====
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});
db.connect(err => {
  if (err) throw err;
  console.log('Conectado a la base de datos');
});

// ===== Middleware global =====
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
  const rutasPublicas = [
    '/api/auth/login',
    '/api/auth/register'
  ];

  if (rutasPublicas.includes(req.path)) {
    return next(); // permitir login y registro
  }

  const rol = req.headers['x-rol'];
  if (!rol) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  req.rol = rol; // asigna rol al request
  next();
});

// ===== Middlewares de autenticación =====
function verificarSesion(req, res, next) {
  const rol = req.headers['x-rol'];
  if (!rol) return res.status(401).json({ error: 'No autenticado' });
  req.rol = rol;
  next();
}

function verificarRol(rolesPermitidos) {
  return (req, res, next) => {
    if (!req.rol) return res.status(401).json({ error: 'No autenticado' });
    if (!rolesPermitidos.includes(req.rol)) {
      return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
  };
}

// ===== AUTH =====

// Registrar usuario
app.post('/api/auth/register', async (req, res) => {
  const { nombre, correo, password, rol } = req.body;
  if (!nombre || !correo || !password)
    return res.status(400).json({ error: 'Faltan campos requeridos' });

  const password_hash = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (?, ?, ?, ?)',
    [nombre, correo, password_hash, rol || 'ASISTENTE'],
    err => {
      if (err) return res.status(500).json({ error: 'Error al registrar usuario' });
      res.json({ mensaje: 'Usuario registrado correctamente' });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { correo, password } = req.body;

  db.query('SELECT * FROM usuarios WHERE correo = ?', [correo], async (err, results) => {
    if (err || results.length === 0)
      return res.status(400).json({ error: 'Usuario no encontrado' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });

    res.json({
      mensaje: 'Login exitoso',
      usuario: { nombre: user.nombre, rol: user.rol }
    });
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.json({ mensaje: 'Logout exitoso. Sesión finalizada.' });
});


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// ===== INSTRUMENTOS =====

// Obtener lista
app.get('/api/instrumentos', verificarSesion, (req, res) => {
  db.query('SELECT * FROM instrumentos', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener instrumentos' });
    res.json(results);
  });
});

// Crear instrumento
app.post(
  '/api/instrumentos',
  verificarSesion,
  verificarRol(['ADMIN', 'ASISTENTE']),
  (req, res) => {
    const { nombre, categoria, estado, ubicacion } = req.body;

    if (!nombre || !categoria)
      return res.status(400).json({ error: 'Datos incompletos' });

    db.query(
      'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?, ?, ?, ?)',
      [nombre, categoria, estado || 'DISPONIBLE', ubicacion || ''],
      err => {
        if (err) return res.status(500).json({ error: 'Error al agregar instrumento' });
        res.json({ mensaje: 'Instrumento agregado correctamente' });
      }
    );
  }
);

// Buscar instrumento
app.get('/api/instrumentos/buscar', verificarSesion, (req, res) => {
  const q = `%${req.query.q || ''}%`;

  db.query(
    'SELECT * FROM instrumentos WHERE nombre LIKE ? OR categoria LIKE ?',
    [q, q],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Error en la búsqueda' });
      res.json(results);
    }
  );
});

// Subir Excel
const upload = multer({ dest: 'uploads/' });
app.post(
  '/api/instrumentos/upload',
  verificarSesion,
  verificarRol(['ADMIN']),
  upload.single('excelFile'),
  (req, res) => {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet);

    data.forEach(item => {
      db.query(
        'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?, ?, ?, ?)',
        [item.nombre, item.categoria, item.estado, item.ubicacion]
      );
    });

    res.json({ mensaje: 'Archivo Excel importado correctamente' });
  }
);

// Descargar Excel
app.get(
  '/api/instrumentos/download',
  verificarSesion,
  verificarRol(['ADMIN']),
  (req, res) => {
    db.query('SELECT * FROM instrumentos', (err, results) => {
      if (err) return res.status(500).json({ error: 'Error al exportar' });

      const ws = xlsx.utils.json_to_sheet(results);
      const wb = xlsx.utils.book_new();

      xlsx.utils.book_append_sheet(wb, ws, 'Instrumentos');

      const filePath = path.join(__dirname, 'uploads', 'instrumentos.xlsx');
      xlsx.writeFile(wb, filePath);

      res.download(filePath);
    });
  }
);

// ===== PRÉSTAMOS =====

// Registrar
app.post(
  '/api/prestamos',
  verificarSesion,
  verificarRol(['ADMIN', 'ASISTENTE']),
  (req, res) => {
    const { instrumento_id, usuario_correo } = req.body;

    if (!instrumento_id || !usuario_correo)
      return res.status(400).json({ error: 'Datos incompletos' });

    db.query(
      'INSERT INTO prestamos (instrumento_id, usuario_correo) VALUES (?, ?)',
      [instrumento_id, usuario_correo],
      err => {
        if (err) return res.status(500).json({ error: 'Error al registrar préstamo' });

        db.query('UPDATE instrumentos SET estado="PRESTADO" WHERE id=?', [
          instrumento_id
        ]);

        res.json({ mensaje: 'Préstamo registrado correctamente' });
      }
    );
  }
);

// Listar préstamos
app.get(
  '/api/prestamos',
  verificarSesion,
  verificarRol(['ADMIN', 'ASISTENTE']),
  (req, res) => {
    db.query(
      `
    SELECT p.id, i.nombre AS instrumento, p.usuario_correo, p.fecha_salida, p.fecha_regreso
    FROM prestamos p
    JOIN instrumentos i ON p.instrumento_id = i.id
  `,
      (err, results) => {
        if (err)
          return res.status(500).json({ error: 'Error al obtener préstamos' });
        res.json(results);
      }
    );
  }
);

// Devolver instrumento
app.put(
  '/api/prestamos/:id/devolver',
  verificarSesion,
  verificarRol(['ADMIN', 'ASISTENTE']),
  (req, res) => {
    db.query(
      'UPDATE prestamos SET fecha_regreso=NOW() WHERE id=?',
      [req.params.id],
      err => {
        if (err)
          return res.status(500).json({ error: 'Error al registrar devolución' });

        db.query(
          'UPDATE instrumentos SET estado="DISPONIBLE" WHERE id = (SELECT instrumento_id FROM prestamos WHERE id=?)',
          [req.params.id]
        );

        res.json({ mensaje: 'Instrumento devuelto correctamente' });
      }
    );
  }
);

// ===== Usuarios (ADMIN) =====
app.get(
  '/api/usuarios',
  verificarSesion,
  verificarRol(['ADMIN']),
  (req, res) => {
    db.query('SELECT id, nombre, correo, rol FROM usuarios', (err, results) => {
      if (err) return res.status(500).json({ error: 'Error al obtener usuarios' });
      res.json(results);
    });
  }
);

// ===== Rutas no encontradas y errores =====
app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
app.use((err, req, res, next) => {
  console.error('Error interno:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ===== Servidor =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Servidor en funcionamiento en el puerto ${PORT}`)
);
