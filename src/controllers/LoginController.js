const crypto = require('crypto');
const { use } = require('../routes/principal');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '../archivos');

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage }).single('file');

function login(req, res) {
    if(req.session.loggedin != true){
        res.render('login/index');
    } else{
        res.redirect('/principal');
    } 
}

function auth(req, res){
    upload(req, res, function (err) {
        const filePath = path.join(uploadDir, req.file.originalname);
        console.log(filePath);
        fs.readFile(filePath, 'utf8', (err, filedata) => {
            // Aquí procesas el contenido del archivo
            fs.unlink(filePath, (err) => {
                const data = req.body;
                req.getConnection((err, conn) => {
                    conn.query('SELECT * FROM registros WHERE matricula = ? OR email = ?', [data.usuario, data.usuario], (err, datos) => {
                        if(datos.length > 0) {
                            const user = datos[0];
                            if(comparePasswords(data.contras, user.password)){
                                if(comparePasswords(filedata, user.comproba)){
                                    req.session.loggedin = true;
                                    req.session.name = user.nombre;
                                    req.session.matricula = user.matricula;
                                    req.session.privateKey = filedata; //tenemos la private key cifrada, no la guardamos en plano
                                    
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

function register(req, res) {
    if(req.session.loggedin != true){
        res.render('login/register');
    } else{
        res.redirect('/principal');
    } 
}

function comparePasswords(plainPassword, hashedPassword) {
    const hashedInputPassword = hashPassword(plainPassword);
    return hashedInputPassword === hashedPassword;
}

function hashPassword(password) {
    const hash = crypto.createHash('sha256')
                       .update(password)
                       .digest('hex');
    return hash;
}


function generateUniqueKeyPair() {
    const { publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return { publicKey, privateKey };
}

function removePemHeaders(pem) {
    const pemLines = pem.split('\n');
    const base64Lines = pemLines.filter(line => {
        return line && !line.startsWith('-----BEGIN') && !line.startsWith('-----END');
    });
    return base64Lines.join('');
}

function XOR_hex(a, b) {
    const buffer1 = Buffer.from(a, 'hex');
    const buffer2 = Buffer.from(b, 'hex');

    // Obtener la longitud máxima entre los dos buffers
    const maxLength = Math.max(buffer1.length, buffer2.length);

    // Realizar la operación XOR a nivel de bits
    let result = '';
    for (let i = 0; i < maxLength; i++) {
        const byte1 = i < buffer1.length ? buffer1[i] : 0;
        const byte2 = i < buffer2.length ? buffer2[i] : 0;
        const xorResult = byte1 ^ byte2;
        result += xorResult.toString(16).padStart(2, '0'); // Convertir resultado a hexadecimal
    }

    return result;
}

// Función para cifrar
function encrypt(text, keyBuffer, iv) {
    const cipher = crypto.createCipheriv('aes-256-ctr', keyBuffer, iv);
    let encrypted = cipher.update(text, 'base64', 'base64'); 
    encrypted += cipher.final('base64');
    return encrypted;
}

function protectkey(usuario, password, privateKey){
    const usr = hashPassword(usuario);
    const pss = hashPassword(password);
    const iv = crypto.randomBytes(16);
    const key = XOR_hex(usr,pss);
    const final = removePemHeaders(privateKey);
    const keyBuffer = Buffer.from(key, 'hex');
    const encryptedText = encrypt(final, keyBuffer, iv);
    const privtofile = iv.toString('base64') + encryptedText;
    return privtofile;
}

function storeUser(req, res) {
    const data = req.body;
    const hashedPassword = hashPassword(data.contras);
    const {publicKey, privateKey} = generateUniqueKeyPair();
    const privtofile = protectkey(userData.matricula, data.contras, privateKey);
    const comproba = hashPassword(privtofile);
    const userData = {
        matricula: data.matricula,
        password: hashedPassword,
        nombre: data.fsname,
        apellidos: data.lsname,
        email: data.email,
        cargo: data.cargo,
        firma: publicKey
    };

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
                    res.redirect('/alerta');
                });
            }
        });
    });
}

function logout(req, res){
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