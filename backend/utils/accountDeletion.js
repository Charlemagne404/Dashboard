const User = require('../models/User');
const GrimoireDeck = require('../models/GrimoireDeck');
const AccountDeletionJob = require('../models/AccountDeletionJob');
const { logError } = require('./safeLog');

const cleanupDeletedAccount = async (userId) => {
  // A failed or concurrently cancelled deletion must never erase a live user's data.
  if (await User.exists({ _id: userId })) return false;
  await GrimoireDeck.deleteMany({ ownerId: userId });
  await AccountDeletionJob.deleteOne({ _id: userId });
  return true;
};

const deleteAccountRecord = async (user) => {
  // Durable intent precedes deletion; restart can finish dependent-data cleanup.
  await AccountDeletionJob.updateOne({ _id: user._id }, { $setOnInsert: { createdAt: new Date() } }, { upsert: true });
  const deleted = await User.deleteOne({ _id: user._id, __v: user.__v });
  if (!deleted.deletedCount) throw Object.assign(new Error('Account changed. Authenticate again before deleting.'), { statusCode: 409 });
  try {
    await cleanupDeletedAccount(user._id);
    return { cleanupPending: false };
  } catch (err) {
    logError('Account deletion cleanup deferred:', err);
    return { cleanupPending: true };
  }
};

const cleanupPendingAccountDeletions = async () => {
  for await (const job of AccountDeletionJob.find({}).cursor()) {
    await cleanupDeletedAccount(job._id);
  }
};
module.exports = { deleteAccountRecord, cleanupDeletedAccount, cleanupPendingAccountDeletions };
