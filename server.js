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






// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));