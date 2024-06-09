const express = require('express');
const PrincipalController = require('../controllers/PrincipalController');

const router = express.Router();

router.get('/principal', PrincipalController.principal);

module.exports = router;