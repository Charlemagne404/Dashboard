const express = require('express');

const auth = require('../middleware/authMiddleware');
const ctrl = require('../controllers/grimoireDeckController');
const asyncHandler = require('../middleware/asyncHandler');
for (const [name, handler] of Object.entries(ctrl)) ctrl[name] = asyncHandler(handler);

const router = express.Router();

router.use(auth);

router.get('/decks', ctrl.listDecks);
router.post('/decks/import', ctrl.importDecks);
router.put('/decks/:deckId', ctrl.saveDeck);
router.delete('/decks/:deckId', ctrl.deleteDeck);

module.exports = router;
