function principal(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/index', {name: req.session.name}); //si existe la sesión
    } 
}

module.exports = {
    principal,
}