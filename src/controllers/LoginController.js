const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Utils = require('../controllers/Utils'); 
const utils = new Utils();

// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '../archivos');

if (!fs.existsSync(uploadDir)) { //Crea la carpeta archivos si aún no existe
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({ //para la subida de archivos
    destination: uploadDir,
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage }).single('file'); //constante para la subida de archivos, esta es la que se manda a llamr

//renderiza la página del login
function login(req, res) {
    if(req.session.loggedin != true){
        res.render('login/index');
    } else{
        res.redirect('/principal');
    } 
}

//renderiza la página de registro
function register(req, res) {
    if(req.session.loggedin != true){
        res.render('login/register');
    } else{
        res.redirect('/principal');
    } 
}

//GENERA UN PAR UNICO DE CLAVES RSA 2048 bits - 256 bytes
function generateUniqueKeyPair() {
    const { publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return { publicKey, privateKey };
}

//COMPRUEBA DATOS DENTRO DEL LOGIN
function auth(req, res){
    upload(req, res, function (err) {
        const filePath = path.join(uploadDir, req.file.originalname);
        fs.readFile(filePath, 'utf8', (err, filedata) => {
            // Aquí procesas el contenido del archivo
            fs.unlink(filePath, (err) => {
                const data = req.body;
                req.getConnection((err, conn) => {
                    conn.query('SELECT * FROM registros WHERE matricula = ? OR email = ?', [data.usuario, data.usuario], (err, datos) => {
                        if(datos.length > 0) {
                            const user = datos[0];
                            if(utils.comparePasswords(data.contras, user.password)){
                                if(utils.comparePasswords(filedata, user.comproba)){
                                    req.session.loggedin = true;
                                    req.session.name = user.nombre;
                                    req.session.matricula = user.matricula;
                                    req.session.privateKey = filedata; //tenemos la private key cifrada, no la guardamos en plano
                                    console.log('INICIO DE SESIÓN ------- WELCOME');
                                    res.redirect('/principal');
                                }else{
                                    res.render('login/index', {error: '* ERROR. This is not your key.'});
                                }
                            } else{
                                res.render('login/index', {error: '* ERROR. Incorrect password.'});
                            }
                        } else {
                            res.render('login/index', {error: '* ERROR. User not exists.'});
                        }
                    });
                });
            });
        });
    });
}

//REGISTRAR USUARIO
function storeUser(req, res) {
    const data = req.body;
    const hashedPassword = utils.calculateHash(data.contras, 'hex');
    const {publicKey, privateKey} = generateUniqueKeyPair();
    console.log('Public key generada: ' + publicKey);
    console.log('Private key generada: ' + privateKey);
    const userData = {
        matricula: data.matricula,
        password: hashedPassword,
        nombre: data.fsname,
        apellidos: data.lsname,
        email: data.email,
        cargo: data.cargo,
        firma: publicKey
    };
    const privtofile = utils.protectkey(userData.matricula, data.contras, privateKey);
    const comproba = utils.calculateHash(privtofile, 'hex');
    

    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM registros WHERE matricula = ?', [data.matricula], (err, datos) => {
            if(datos.length > 0) {
                res.render('login/register', {error: '* ERROR User alredy exists.'});
            } else {
                const query = 'INSERT INTO registros (matricula, password, nombre, apellidos, email, cargo, firma, comproba) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
                const values = [
                    userData.matricula,
                    userData.password,
                    userData.nombre,
                    userData.apellidos,
                    userData.email,
                    userData.cargo,
                    userData.firma,
                    comproba
                ];

                conn.query(query, values, (err, result) => {
                    if (err) {
                        console.error('Query error:', err);
                        return;
                    }
                    req.session.loggedin = true;
                    req.session.name = userData.nombre;
                    req.session.matricula = userData.matricula;
                    req.session.protectKey = privtofile;
                    req.session.privateKey = privtofile;
                    console.log('INICIO DE SESIÓN ------- WELCOME');
                    res.redirect('/alerta');
                });
            }
        });
    });
}

//CERRAR SESIÓN
function logout(req, res){
    
    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }
        conn.query('SELECT name FROM archivos WHERE recibe = ? AND tipo = "Conf"', [req.session.matricula], (err, results) => {
            if (err) {
                console.error('Error fetching users from the database:', err);
            }
            if (results.length > 0) {
                const nombresArchivos = results.map(result => result.name);
                nombresArchivos.forEach(name => {
                    // Agregar el prefijo "temp_" al nombre original
                    const tempName = 'temp_' + name;
                    if(fs.existsSync(path.join(uploadDir, tempName))){
                        fs.unlink(path.join(uploadDir, tempName), (err) => {
                            if (err) {
                                console.error('Error deleting file:', err);
                            }
                        });
                    }
                });
            }                    
        });
    });
    console.log('CERRAR SESIÓN ------- BYE BYE');
    if(req.session.loggedin == true){
        req.session.destroy();
    }
    res.redirect('/');
}

module.exports = {
    login: login,
    register: register,
    storeUser: storeUser,
    auth: auth,
    logout,
}