const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
require('dotenv').config();

// Configuración de la base de datos
    const db = mysql.createConnection({
    host: process.env.DB_HOST,       // Host desde .env
    user: process.env.DB_USER,       // Usuario desde .env
    password: process.env.DB_PASS,   // Contraseña desde .env
    database: process.env.DB_NAME    // Nombre de la base de datos desde .env
});
db.connect(err => {
  if (err) throw err;
  console.log('Conectado a la base de datos');
});

// Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.get('/api/test', (req, res) => {
  db.query('SELECT NOW() AS hora_actual', (err, result) => {
    if (err) return res.status(500).json({ error: 'Error en la conexión' });
    res.json({ mensaje: 'Servidor y BD OK', resultado: result });
  });
});



// Registrar usuario
app.post('/api/auth/register', async (req, res) => {
  const { nombre, correo, password, rol } = req.body;
  if (!nombre || !correo || !password) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  const password_hash = await bcrypt.hash(password, 10);
  db.query(
    'INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (?, ?, ?, ?)',
    [nombre, correo, password_hash, rol || 'ASISTENTE'],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Error al registrar usuario' });
      res.json({ mensaje: 'Usuario registrado correctamente' });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { correo, password } = req.body;
  db.query('SELECT * FROM usuarios WHERE correo = ?', [correo], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'Usuario no encontrado' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });
    res.json({ mensaje: 'Login exitoso', usuario: { nombre: user.nombre, rol: user.rol } });
  });
});


// Obtener todos los instrumentos
app.get('/api/instrumentos', (req, res) => {
  db.query('SELECT * FROM instrumentos', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener instrumentos' });
    res.json(results);
  });
});

// Agregar instrumento
app.post('/api/instrumentos', (req, res) => {
  const { nombre, categoria, estado, ubicacion } = req.body;
  if (!nombre || !categoria) return res.status(400).json({ error: 'Datos incompletos' });

  db.query(
    'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?, ?, ?, ?)',
    [nombre, categoria, estado || 'DISPONIBLE', ubicacion || ''],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Error al agregar instrumento' });
      res.json({ mensaje: 'Instrumento agregado' });
    }
  );
});


app.get('/api/instrumentos/buscar', (req, res) => {
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


const upload = multer({ dest: 'uploads/' });

// Subir Excel
app.post('/api/instrumentos/upload', upload.single('excelFile'), (req, res) => {
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
});

// Descargar Excel
app.get('/api/instrumentos/download', (req, res) => {
  db.query('SELECT * FROM instrumentos', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al exportar' });
    const ws = xlsx.utils.json_to_sheet(results);
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, ws, 'Instrumentos');
    const filePath = path.join(__dirname, 'uploads', 'instrumentos.xlsx');
    xlsx.writeFile(wb, filePath);
    res.download(filePath);
  });
});




// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));