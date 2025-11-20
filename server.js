// ===== Dependencias =====
const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
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
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conectado a la base de datos');
});

// ===== Middleware global =====
app.use(express.static(path.join(__dirname, 'public'), {
  index: false
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuración de la sesión
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretKey',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Middleware de debug
app.use((req, res, next) => {
  console.log('=== DEBUG REQUEST ===');
  console.log('Method:', req.method);
  console.log('URL:', req.url);
  console.log('Body:', req.body);
  console.log('Session:', req.session);
  console.log('=====================');
  next();
});

// ===== Middlewares de autenticación =====
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

function requireRole(allowedRoles) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.rol)) {
      next();
    } else {
      let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1>Acceso denegado</h1>
        <p>No tienes permisos para acceder a esta página.</p>
        <button onclick="window.location.href='/'">Volver al inicio</button>
      </body>
      </html>
      `;
      res.status(403).send(html);
    }
  };
}

// Middleware para verificar sesión en APIs
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  next();
}

// ===== RUTAS PÚBLICAS =====

// Servir páginas de login y registro
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/registro', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registro.html'));
});

// Login para API (compatible con frontend)
app.post('/api/auth/login', async (req, res) => {
  console.log('=== LOGIN API ATTEMPT ===');
  console.log('Correo:', req.body.correo);
  
  const { correo, password } = req.body;
  
  if (!correo || !password) {
    return res.status(400).json({ 
      error: 'Correo y contraseña son requeridos' 
    });
  }

  const query = 'SELECT * FROM usuarios WHERE correo = ?';
  db.query(query, [correo], async (err, results) => {
    if (err) {
      console.error('Error en login DB:', err);
      return res.status(500).json({ 
        error: 'Error en el servidor' 
      });
    }

    if (results.length === 0) {
      console.log('Usuario no encontrado:', correo);
      return res.status(401).json({ 
        error: 'Usuario no encontrado' 
      });
    }

    const user = results[0];
    console.log('Usuario encontrado:', user.nombre);
    
    try {
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      
      if (!isPasswordValid) {
        console.log('Contraseña incorrecta para:', correo);
        return res.status(401).json({ 
          error: 'Contraseña incorrecta' 
        });
      }

      // Establecer sesión
      req.session.userId = user.id;
      req.session.user = {
        id: user.id,
        nombre: user.nombre,
        correo: user.correo,
        rol: user.rol
      };

      console.log('Login API exitoso, usuario:', user.nombre);
      
      // Respuesta que espera el frontend
      res.json({
        mensaje: 'Login exitoso',
        usuario: {
          id: user.id,
          nombre: user.nombre,
          rol: user.rol
        }
      });

    } catch (compareError) {
      console.error('Error comparando passwords:', compareError);
      res.status(500).json({ 
        error: 'Error en el servidor' 
      });
    }
  });
});

// Registro de usuario (formulario HTML)
app.post('/registrar', async (req, res) => {
  const { nombre, correo, password, codigo_acceso } = req.body;
  
  if (!nombre || !correo || !password || !codigo_acceso) {
    return res.send('Todos los campos son obligatorios');
  }

  try {
    const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
    db.query(query, [codigo_acceso], async (err, results) => {
      if (err) {
        console.error('Error en consulta de código:', err);
        return res.send('Error en el servidor');
      }
      
      if (results.length === 0) {
        return res.send('Código de acceso inválido');
      }

      const tipo_usuario = results[0].tipo_usuario;
      
      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const insertUser = 'INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (?, ?, ?, ?)';
        db.query(insertUser, [nombre, correo, hashedPassword, tipo_usuario], (err) => {
          if (err) {
            console.error('Error al registrar usuario:', err);
            return res.send('Error al registrar usuario');
          }
          res.redirect('/login');
        });
      } catch (hashError) {
        console.error('Error al hashear password:', hashError);
        res.send('Error en el servidor');
      }
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.send('Error en el servidor');
  }
});

// Login (formulario HTML)
app.post('/login', async (req, res) => {
  const { correo, password } = req.body;
  
  if (!correo || !password) {
    return res.send('Correo y contraseña son requeridos');
  }

  const query = 'SELECT * FROM usuarios WHERE correo = ?';
  db.query(query, [correo], async (err, results) => {
    if (err) {
      console.error('Error en login:', err);
      let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1>Error al iniciar sesión</h1>
        <button onclick="window.location.href='/login'">Volver al login</button>
      </body>
      </html>
      `;
      return res.send(html);
    }

    if (results.length === 0) {
      let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1>Usuario no encontrado</h1>
        <button onclick="window.location.href='/login'">Volver al login</button>
      </body>
      </html>
      `;
      return res.send(html);
    }

    const user = results[0];
    
    try {
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      
      if (!isPasswordValid) {
        let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Error</title>
        </head>
        <body>
          <h1>Contraseña incorrecta</h1>
          <button onclick="window.location.href='/login'">Volver al login</button>
        </body>
        </html>
        `;
        return res.send(html);
      }

      // Establecer sesión
      req.session.userId = user.id;
      req.session.user = {
        id: user.id,
        nombre: user.nombre,
        correo: user.correo,
        rol: user.rol
      };

      res.redirect('/');
    } catch (compareError) {
      console.error('Error comparando passwords:', compareError);
      let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Error</title>
        </head>
        <body>
          <h1>Error en el servidor</h1>
          <button onclick="window.location.href='/login'">Volver al login</button>
        </body>
        </html>
        `;
        res.send(html);
    }
  });
});

// ===== RUTAS PROTEGIDAS =====

// Ruta principal protegida
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Servir páginas protegidas
app.get('/instrumentos.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'instrumentos.html'));
});

app.get('/busqueda.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'busqueda.html'));
});

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.rol });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ===== INSTRUMENTOS =====

// Obtener lista
app.get('/api/instrumentos', requireAuth, (req, res) => {
  db.query('SELECT * FROM instrumentos', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener instrumentos' });
    res.json(results);
  });
});

// Crear instrumento
app.post(
  '/api/instrumentos',
  requireAuth,
  requireRole(['ADMIN', 'ASISTENTE']),
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
app.get('/api/instrumentos/buscar', requireAuth, (req, res) => {
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
  requireAuth,
  requireRole(['ADMIN']),
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
  requireAuth,
  requireRole(['ADMIN']),
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
  requireAuth,
  requireRole(['ADMIN', 'ASISTENTE']),
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
  requireAuth,
  requireRole(['ADMIN', 'ASISTENTE']),
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
  requireAuth,
  requireRole(['ADMIN', 'ASISTENTE']),
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
  requireAuth,
  requireRole(['ADMIN']),
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