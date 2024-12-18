const express = require('express');
const { engine } = require('express-handlebars');
const myConnection = require('express-myconnection');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const handlebars = require('handlebars');

const loginRoutes = require('./routes/login');
const princRoutes = require('./routes/principal');
const crifRoutes = require('./routes/cifrado');

const app = express();
app.set('port', 4000);

handlebars.registerHelper('encodeURIComponent', function(str) {
    return encodeURIComponent(str);
  });

// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '/archivos');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use('/archivos', express.static(uploadDir));

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

app.listen(app.get('port'), () => {
    console.log('Servidor iniciado en http://localhost:'+app.get('port'));
});

app.get('/', (req, res) => { //ruta raíz
    if(req.session.loggedin == true){
        if (req.session.protectKey && req.session.protectKey.trim() !== '') {
            delete req.session.protectKey; //si la sesión esta iniciada y cambió de página, se borra el nombre del arch. temporal.
        }
        res.redirect('/principal');
    } else{
        res.render('home');
    }
});

app.use('/', loginRoutes);
app.use('/', princRoutes);
app.use('/', crifRoutes);

// Configurar Express para servir archivos estáticos
app.use(express.static('public'));