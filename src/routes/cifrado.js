const express = require('express');
const path = require('path');
const PrincipalController = require('../controllers/CifradoController');

const router = express.Router();

//router.get('/crearDocumento', PrincipalController.crearDocumento);
router.post('/crearDocumento', PrincipalController.crearDocumento);

module.exports = router;