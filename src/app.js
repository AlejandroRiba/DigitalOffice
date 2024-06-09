const express = require('express');
const { engine } = require('express-handlebars');
const myConnection = require('express-myconnection');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');

const loginRoutes = require('./routes/login');
const princRoutes = require('./routes/principal');

const app = express();
app.set('port', 4000);


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
    console.log('Listening on port ', app.get('port'));
});

app.use('/', loginRoutes);
app.use('/', princRoutes);

app.get('/', (req, res) => { //ruta raíz
    if(req.session.loggedin == true){
        res.render('principal/index', {name: req.session.name});
    } else{
        res.render('home');
    }
});

// Configurar Express para servir archivos estáticos
app.use(express.static('public'));
