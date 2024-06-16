const crypto = require('crypto');
const { use } = require('../routes/principal');

function login(req, res) {
    if(req.session.loggedin != true){
        res.render('login/index');
    } else{
        res.redirect('/principal');
    } 
}

function auth(req, res){
    const data = req.body;
    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM registros WHERE matricula = ? OR email = ?', [data.usuario, data.usuario], (err, datos) => {
            if(datos.length > 0) {
              const user = datos[0];
              if(comparePasswords(data.contras, user.password)){
                req.session.loggedin = true;
                req.session.name = user.nombre;
                req.session.matricula = user.matricula;

                res.redirect('/principal');

              } else{
                res.render('login/index', {error: '* ERROR. Incorrect password.'});
              }
            } else {
                res.render('login/index', {error: '* ERROR. User not exists.'});
            }
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

function storeUser(req, res) {
    const data = req.body;
    const hashedPassword = hashPassword(data.contras);
    const hashedUser = hashPassword(data.matricula);
    data.contras = hashedPassword;
    const {publicKey, privateKey} = generateUniqueKeyPair();
    const newpublicKey = removePemHeaders(publicKey);
    const newprivateKey = removePemHeaders(privateKey);
    console.log(newprivateKey);
    const userData = {
        matricula: data.matricula,
        password: data.contras,
        nombre: data.fsname,
        apellidos: data.lsname,
        email: data.email,
        cargo: data.cargo,
        firma: newpublicKey
    };

    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM registros WHERE matricula = ?', [data.matricula], (err, datos) => {
            if(datos.length > 0) {
                res.render('login/register', {error: '* ERROR User alredy exists.'});
            } else {
                req.getConnection((err, conn) => {
                    if (err) {
                        console.error('Database connection error:', err);
                        return;
                    }
                    const query = 'INSERT INTO registros (matricula, password, nombre, apellidos, email, cargo, firma) VALUES (?, ?, ?, ?, ?, ?, ?)';
                    const values = [
                        userData.matricula,
                        userData.password,
                        userData.nombre,
                        userData.apellidos,
                        userData.email,
                        userData.cargo,
                        userData.firma
                    ];

                    conn.query(query, values, (err, result) => {
                        if (err) {
                            console.error('Query error:', err);
                            return;
                        }

                        const query1 = 'INSERT INTO private (usuario, password, `key`) VALUES (?, ?, ?)';
                        const values2 = [hashedUser, userData.password, newprivateKey]
                        conn.query(query1, values2, (err, result) => {
                            if (err) {
                                console.error('Query error:', err);
                                return;
                            }
                        });
                        req.session.loggedin = true;
                        req.session.name = userData.nombre;
                        req.session.matricula = userData.matricula;
                        res.redirect('/principal');
                    });
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