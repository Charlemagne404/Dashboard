#!/usr/bin/env node
require('dotenv').config();

const mongoose = require('mongoose');
const User = require('../models/User');

const usage = () => {
  console.log('Usage: node scripts/setOwnerAccount.js <email> [--demote]');
};

const run = async () => {
  const [, , emailArg, modeArg] = process.argv;
  const email = String(emailArg || '').trim().toLowerCase();
  const demote = String(modeArg || '').trim() === '--demote';

  if (!email) {
    usage();
    process.exitCode = 1;
    return;
  }

  if (!process.env.MONGO_URI) {
    throw new Error('MONGO_URI is required.');
  }

  await mongoose.connect(process.env.MONGO_URI, {
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
  });

  try {
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error(`No user found for ${email}.`);
    }
    if (!demote && (!user.isVerified || user.accountStatus !== 'active')) {
      throw new Error('Owner promotion requires a verified, active account.');
    }
    if (demote && user.accountRole === 'owner' && !(await User.exists({
      _id: { $ne: user._id }, accountRole: 'owner', accountStatus: 'active',
    }))) throw new Error('An active owner must remain.');

    user.accountRole = demote ? 'user' : 'owner';
    user.auditEvents.push({ type: 'owner_role_changed', message: 'Owner authority updated by local operator.', meta: { role: user.accountRole } });
    user.auditEvents = user.auditEvents.slice(-120);
    await user.save();

    console.log(
      `${demote ? 'Demoted' : 'Promoted'} ${email} to ${user.accountRole} (status: ${user.accountStatus}).`
    );
  } finally {
    await mongoose.disconnect();
  }
};

run().catch((err) => {
  console.error(err.message || err);
  process.exitCode = 1;
});
