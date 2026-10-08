const GrimoireDeck = require('../models/GrimoireDeck');
const { logError } = require('../utils/safeLog');

const DECK_FORMATS = new Set([
  'standard',
  'pioneer',
  'modern',
  'legacy',
  'vintage',
  'pauper',
  'commander',
]);
const CARD_COLORS = new Set(['W', 'U', 'B', 'R', 'G']);
const MAX_DECKS_PER_USER = 120;
const MAX_DECKS_PER_IMPORT = 40;
const MAX_MAINBOARD_ENTRIES = 250;
const MAX_SIDEBOARD_ENTRIES = 120;
const MAX_MAINBOARD_TOTAL = 400;
const MAX_SIDEBOARD_TOTAL = 250;
const MAX_LEGALITY_ENTRIES = 80;

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
const toObjectIdString = (value) => String(value || '');
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);

const isRecord = (value) => typeof value === 'object' && value !== null;

const parseIsoDate = (value, fallback = new Date()) => {
  const candidate = new Date(String(value || '').trim());
  return Number.isNaN(candidate.getTime()) ? fallback : candidate;
};

const parseNullableNumber = (value, field, max = 100000) => {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > max) {
    throw new Error(`${field} must be a non-negative number.`);
  }

  return value;
};

const normalizeColorArray = (value, field) => {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array.`);
  }

  return value.map((entry) => {
    const color = sanitizeText(entry, 4).toUpperCase();
    if (!CARD_COLORS.has(color)) {
      throw new Error(`${field} contains an invalid color value.`);
    }
    return color;
  });
};

const normalizeLegalities = (value) => {
  if (!isRecord(value)) {
    return {};
  }

  const normalized = {};
  let count = 0;

  for (const [rawKey, rawValue] of Object.entries(value)) {
    if (count >= MAX_LEGALITY_ENTRIES) {
      break;
    }

    const key = sanitizeText(rawKey, 40).toLowerCase();
    const legality = sanitizeText(rawValue, 24).toLowerCase();

    if (!key || !legality) {
      continue;
    }

    normalized[key] = legality;
    count += 1;
  }

  return normalized;
};

const normalizeCardSnapshot = (value) => {
  if (!isRecord(value)) {
    throw new Error('Each saved deck entry must include a card snapshot.');
  }

  const manaValue = parseNullableNumber(value.manaValue, 'card.manaValue', 100);
  if (manaValue === null) {
    throw new Error('card.manaValue is required.');
  }

  const prices = isRecord(value.prices) ? value.prices : {};

  return {
    id: sanitizeText(value.id, 120),
    oracleId: sanitizeText(value.oracleId, 120) || null,
    name: sanitizeText(value.name, 200),
    manaCost: sanitizeText(value.manaCost, 80),
    manaValue,
    releasedAt: sanitizeText(value.releasedAt, 20),
    typeLine: sanitizeText(value.typeLine, 240),
    oracleText: sanitizeText(value.oracleText, 6000),
    colors: normalizeColorArray(Array.isArray(value.colors) ? value.colors : [], 'card.colors'),
    colorIdentity: normalizeColorArray(
      Array.isArray(value.colorIdentity) ? value.colorIdentity : [],
      'card.colorIdentity'
    ),
    setCode: sanitizeText(value.setCode, 20).toLowerCase(),
    setName: sanitizeText(value.setName, 120),
    collectorNumber: sanitizeText(value.collectorNumber, 40),
    rarity: sanitizeText(value.rarity, 40).toLowerCase(),
    legalities: normalizeLegalities(value.legalities),
    imageUrl: sanitizeText(value.imageUrl, 1000),
    largeImageUrl: sanitizeText(value.largeImageUrl, 1000),
    prices: {
      usd: parseNullableNumber(prices.usd, 'card.prices.usd'),
      usdFoil: parseNullableNumber(prices.usdFoil, 'card.prices.usdFoil'),
      eur: parseNullableNumber(prices.eur, 'card.prices.eur'),
      eurFoil: parseNullableNumber(prices.eurFoil, 'card.prices.eurFoil'),
      tix: parseNullableNumber(prices.tix, 'card.prices.tix'),
    },
  };
};

const normalizeDeckEntries = (value, field, maxEntries, maxTotalQuantity) => {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array.`);
  }

  if (value.length > maxEntries) {
    throw new Error(`${field} has too many unique card entries.`);
  }

  const entries = value.map((entry) => {
    if (!isRecord(entry)) {
      throw new Error(`${field} contains an invalid entry.`);
    }

    if (
      typeof entry.quantity !== 'number' ||
      !Number.isInteger(entry.quantity) ||
      entry.quantity < 1 ||
      entry.quantity > 250
    ) {
      throw new Error(`${field} contains an invalid quantity.`);
    }

    return {
      quantity: entry.quantity,
      card: normalizeCardSnapshot(entry.card),
    };
  });

  const totalQuantity = entries.reduce((sum, entry) => sum + entry.quantity, 0);
  if (totalQuantity > maxTotalQuantity) {
    throw new Error(`${field} exceeds the supported card total.`);
  }

  return entries;
};

const normalizeDeckInput = (value, expectedDeckId = '') => {
  if (!isRecord(value)) {
    throw new Error('Deck payload must be an object.');
  }

  const deckId = sanitizeText(expectedDeckId || value.id, 120);
  if (!deckId) {
    throw new Error('Deck id is required.');
  }

  if (expectedDeckId && hasOwn(value, 'id') && sanitizeText(value.id, 120) !== deckId) {
    throw new Error('Deck id does not match the request path.');
  }

  const format = sanitizeText(value.format, 40).toLowerCase();
  if (!DECK_FORMATS.has(format)) {
    throw new Error('Deck format is invalid.');
  }

  const name = sanitizeText(value.name, 120);
  if (!name) {
    throw new Error('Deck name is required.');
  }

  const deckCreatedAt = parseIsoDate(value.createdAt, new Date());
  const deckUpdatedAt = parseIsoDate(value.updatedAt, deckCreatedAt);

  const mainboard = normalizeDeckEntries(
    Array.isArray(value.mainboard) ? value.mainboard : [],
    'mainboard',
    MAX_MAINBOARD_ENTRIES,
    MAX_MAINBOARD_TOTAL
  );
  const sideboard = normalizeDeckEntries(
    Array.isArray(value.sideboard) ? value.sideboard : [],
    'sideboard',
    MAX_SIDEBOARD_ENTRIES,
    MAX_SIDEBOARD_TOTAL
  );

  if (mainboard.length === 0 && sideboard.length === 0) {
    throw new Error('A saved deck must contain at least one card.');
  }

  return {
    deckId,
    name,
    format,
    mainboard,
    sideboard,
    notes: sanitizeText(value.notes, 8000),
    matchupNotes: sanitizeText(value.matchupNotes, 8000),
    budgetTargetUsd: parseNullableNumber(value.budgetTargetUsd, 'budgetTargetUsd'),
    deckCreatedAt,
    deckUpdatedAt: deckUpdatedAt < deckCreatedAt ? deckCreatedAt : deckUpdatedAt,
  };
};

const serializeDeck = (deck) => ({
  id: sanitizeText(deck.deckId, 120),
  name: sanitizeText(deck.name, 120) || 'Untitled Deck',
  format: DECK_FORMATS.has(sanitizeText(deck.format, 40).toLowerCase())
    ? sanitizeText(deck.format, 40).toLowerCase()
    : 'standard',
  createdAt: new Date(deck.deckCreatedAt || deck.createdAt || Date.now()).toISOString(),
  updatedAt: new Date(deck.deckUpdatedAt || deck.updatedAt || Date.now()).toISOString(),
  mainboard: Array.isArray(deck.mainboard) ? deck.mainboard : [],
  sideboard: Array.isArray(deck.sideboard) ? deck.sideboard : [],
  notes: sanitizeText(deck.notes, 8000),
  matchupNotes: sanitizeText(deck.matchupNotes, 8000),
  budgetTargetUsd:
    typeof deck.budgetTargetUsd === 'number' && Number.isFinite(deck.budgetTargetUsd)
      ? deck.budgetTargetUsd
      : null,
});

const listDecksForUser = async (userId) => {
  const decks = await GrimoireDeck.find({ ownerId: userId })
    .sort({ deckUpdatedAt: -1, _id: -1 })
    .lean();

  return decks.map((deck) => serializeDeck(deck));
};

const ensureDeckCapacity = async (userId, incomingDeckIds) => {
  const existingDecks = await GrimoireDeck.find({ ownerId: userId }).select('deckId').lean();
  const existingIds = new Set(existingDecks.map((deck) => sanitizeText(deck.deckId, 120)));
  const incomingNewIds = incomingDeckIds.filter((deckId) => deckId && !existingIds.has(deckId));

  if (existingIds.size + incomingNewIds.length > MAX_DECKS_PER_USER) {
    throw new Error(`Grimoire cloud sync supports up to ${MAX_DECKS_PER_USER} saved decks per account.`);
  }
};

const dedupeIncomingDecks = (decks) => {
  const map = new Map();

  for (const deck of decks) {
    const current = map.get(deck.deckId);
    if (!current) {
      map.set(deck.deckId, deck);
      continue;
    }

    if (deck.deckUpdatedAt.getTime() >= current.deckUpdatedAt.getTime()) {
      map.set(deck.deckId, deck);
    }
  }

  return Array.from(map.values());
};

const getDeckTimestampMs = (value) => {
  const timestamp = new Date(value || 0).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
};

const isIncomingDeckStale = (incomingDeck, existingDeck) =>
  getDeckTimestampMs(existingDeck?.deckUpdatedAt) > getDeckTimestampMs(incomingDeck?.deckUpdatedAt);

exports.listDecks = async (req, res) => {
  try {
    const decks = await listDecksForUser(req.user.id);
    return res.status(200).json({
      decks,
      syncedAt: new Date().toISOString(),
      continentalId: toObjectIdString(req.user.id),
    });
  } catch (err) {
    logError('List Grimoire decks error:', err);
    return res.status(500).json({ message: 'Failed to load Grimoire decks.' });
  }
};

exports.saveDeck = async (req, res) => {
  const deckId = sanitizeText(req.params.deckId, 120);

  try {
    const normalizedDeck = normalizeDeckInput(req.body || {}, deckId);
    await ensureDeckCapacity(req.user.id, [normalizedDeck.deckId]);

    const existingDeck = await GrimoireDeck.findOne({
      ownerId: req.user.id,
      deckId: normalizedDeck.deckId,
    }).select('_id deckUpdatedAt');

    if (isIncomingDeckStale(normalizedDeck, existingDeck)) {
      return res.status(409).json({
        message:
          'This deck has a newer version on the server. Refresh the latest decks before syncing again.',
        deckId: normalizedDeck.deckId,
        serverUpdatedAt: existingDeck.deckUpdatedAt,
      });
    }

    const deck = await GrimoireDeck.findOneAndUpdate(
      {
        ownerId: req.user.id,
        deckId: normalizedDeck.deckId,
      },
      {
        $set: {
          ownerId: req.user.id,
          deckId: normalizedDeck.deckId,
          name: normalizedDeck.name,
          format: normalizedDeck.format,
          mainboard: normalizedDeck.mainboard,
          sideboard: normalizedDeck.sideboard,
          notes: normalizedDeck.notes,
          matchupNotes: normalizedDeck.matchupNotes,
          budgetTargetUsd: normalizedDeck.budgetTargetUsd,
          deckCreatedAt: normalizedDeck.deckCreatedAt,
          deckUpdatedAt: normalizedDeck.deckUpdatedAt,
        },
      },
      {
        new: true,
        upsert: true,
        runValidators: true,
        setDefaultsOnInsert: true,
      }
    ).lean();

    return res.status(existingDeck ? 200 : 201).json({
      message: existingDeck ? 'Deck synced.' : 'Deck created.',
      deck: serializeDeck(deck),
      syncedAt: new Date().toISOString(),
      continentalId: toObjectIdString(req.user.id),
    });
  } catch (err) {
    if (err instanceof Error) {
      return res.status(400).json({ message: err.message });
    }

    logError('Save Grimoire deck error:', err);
    return res.status(500).json({ message: 'Failed to save the Grimoire deck.' });
  }
};

exports.importDecks = async (req, res) => {
  const rawDecks = Array.isArray(req.body?.decks) ? req.body.decks : null;

  if (!rawDecks) {
    return res.status(400).json({ message: 'Deck import payload must include a decks array.' });
  }

  if (rawDecks.length > MAX_DECKS_PER_IMPORT) {
    return res.status(400).json({
      message: `A single import can sync at most ${MAX_DECKS_PER_IMPORT} decks.`,
    });
  }

  try {
    const normalizedDecks = dedupeIncomingDecks(rawDecks.map((deck) => normalizeDeckInput(deck)));
    const staleDeckIds = [];

    if (normalizedDecks.length > 0) {
      await ensureDeckCapacity(
        req.user.id,
        normalizedDecks.map((deck) => deck.deckId)
      );

      const existingDecks = await GrimoireDeck.find({
        ownerId: req.user.id,
        deckId: { $in: normalizedDecks.map((deck) => deck.deckId) },
      })
        .select('deckId deckUpdatedAt')
        .lean();
      const existingDeckMap = new Map(
        existingDecks.map((deck) => [sanitizeText(deck.deckId, 120), deck])
      );
      const decksToWrite = normalizedDecks.filter((deck) => {
        const existingDeck = existingDeckMap.get(deck.deckId);
        if (!isIncomingDeckStale(deck, existingDeck)) {
          return true;
        }
        staleDeckIds.push(deck.deckId);
        return false;
      });

      if (decksToWrite.length > 0) {
        await GrimoireDeck.bulkWrite(
          decksToWrite.map((deck) => ({
            updateOne: {
              filter: {
                ownerId: req.user.id,
                deckId: deck.deckId,
              },
              update: {
                $set: {
                  ownerId: req.user.id,
                  deckId: deck.deckId,
                  name: deck.name,
                  format: deck.format,
                  mainboard: deck.mainboard,
                  sideboard: deck.sideboard,
                  notes: deck.notes,
                  matchupNotes: deck.matchupNotes,
                  budgetTargetUsd: deck.budgetTargetUsd,
                  deckCreatedAt: deck.deckCreatedAt,
                  deckUpdatedAt: deck.deckUpdatedAt,
                },
              },
              upsert: true,
            },
          })),
          { ordered: false }
        );
      }
    }

    const decks = await listDecksForUser(req.user.id);
    return res.status(200).json({
      message: staleDeckIds.length
        ? 'Deck import completed. Some stale decks were skipped because the server has newer versions.'
        : 'Deck import completed.',
      decks,
      importedCount: normalizedDecks.length - staleDeckIds.length,
      staleDeckIds,
      syncedAt: new Date().toISOString(),
      continentalId: toObjectIdString(req.user.id),
    });
  } catch (err) {
    if (err instanceof Error) {
      return res.status(400).json({ message: err.message });
    }

    logError('Import Grimoire decks error:', err);
    return res.status(500).json({ message: 'Failed to import Grimoire decks.' });
  }
};

exports.deleteDeck = async (req, res) => {
  const deckId = sanitizeText(req.params.deckId, 120);
  if (!deckId) {
    return res.status(400).json({ message: 'Deck id is required.' });
  }

  try {
    await GrimoireDeck.findOneAndDelete({
      ownerId: req.user.id,
      deckId,
    });

    return res.status(200).json({
      message: 'Deck deleted.',
      deckId,
      syncedAt: new Date().toISOString(),
      continentalId: toObjectIdString(req.user.id),
    });
  } catch (err) {
    logError('Delete Grimoire deck error:', err);
    return res.status(500).json({ message: 'Failed to delete the Grimoire deck.' });
  }
};
