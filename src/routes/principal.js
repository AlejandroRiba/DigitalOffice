const express = require('express');
const path = require('path');
const PrincipalController = require('../controllers/PrincipalController');

const router = express.Router();

router.get('/principal', PrincipalController.principal);
router.post('/principal', PrincipalController.generatesignature);
router.get('/uploadf', PrincipalController.uploadf);
router.post('/uploadf', PrincipalController.uploadMinut);
router.get('/uploadm', PrincipalController.uploadm);
router.post('/uploadm', PrincipalController.uploadMemo);
router.get('/firmar', PrincipalController.firmar);

router.get('/download', function(req, res) {
    const uploadedFileName = req.session.uploadedFileName; // Obtén el nombre del archivo de la sesión
    if (!uploadedFileName) {
        return res.status(404).send('No se encontró ningún archivo');
    }
    const filePath = path.join(__dirname, '../archivos', uploadedFileName);
    res.download(filePath);
});

module.exports = router;