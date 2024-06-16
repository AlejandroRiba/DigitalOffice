const express = require('express');
const { engine } = require('express-handlebars');
const myConnection = require('express-myconnection');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const loginRoutes = require('./routes/login');
const princRoutes = require('./routes/principal');

const app = express();
app.set('port', 4000);

// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '/archivos');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });


app.set('views', __dirname + '/views');
app.engine('.hbs', engine({
    extname: '.hbs',
}));
app.set('view engine', 'hbs');

app.use(bodyParser.urlencoded({
    extended: true,
}));
app.use(bodyParser.json());

app.use(myConnection(mysql, {
    host: 'localhost',
    user: 'root',
    password: '',
    port: '3306',
    database: 'employees'
}));

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

app.post('/cargar', upload.single('file'), (req, res) => {
    const archivo = req.file;
    if (!archivo) {
      return res.status(400).json({ mensaje: 'No se recibió ningún archivo' });
    }
    res.json({ mensaje: 'Archivo recibido con éxito', archivo });
});

app.listen(app.get('port'), () => {
    console.log('Servidor iniciado en http://localhost:'+app.get('port'));
});

app.use('/', loginRoutes);
app.use('/', princRoutes);

// Configurar Express para servir archivos estáticos
app.use(express.static('public'));