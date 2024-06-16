const express = require('express');
const PrincipalController = require('../controllers/PrincipalController');

const router = express.Router();

router.get('/principal', PrincipalController.principal);
router.post('/principal', PrincipalController.generatesignature);
router.get('/uploadf', PrincipalController.uploadf);
router.post('/uploadf', PrincipalController.uploadFile);

module.exports = router;