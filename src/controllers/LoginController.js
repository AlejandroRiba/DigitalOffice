const crypto = require('crypto');

function login(req, res) {
    if(req.session.loggedin != true){
        res.render('login/index');
    } else{
        res.redirect('/');
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
                req.session.name = user.matricula;

                res.redirect('/');

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
        res.redirect('/');
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

function storeUser(req, res) {
    const data = req.body;
    const hashedPassword = hashPassword(data.contras);
    data.contras = hashedPassword;
    const userData = {
        matricula: data.matricula,
        password: data.contras,
        nombre: data.fsname,
        apellidos: data.lsname,
        email: data.email,
        cargo: data.cargo
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
                    const query = 'INSERT INTO registros (matricula, password, nombre, apellidos, email, cargo) VALUES (?, ?, ?, ?, ?, ?)';
                    const values = [
                        userData.matricula,
                        userData.password,
                        userData.nombre,
                        userData.apellidos,
                        userData.email,
                        userData.cargo
                    ];

                    conn.query(query, values, (err, result) => {
                        if (err) {
                            console.error('Query error:', err);
                            return;
                        }
                        req.session.loggedin = true;
                        req.session.name = userData.matricula;
                        res.redirect('/');
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