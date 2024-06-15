const express = require('express');
const PrincipalController = require('../controllers/PrincipalController');

const router = express.Router();

router.get('/principal', PrincipalController.principal);
router.post('/principal', PrincipalController.generatekey);

module.exports = router;