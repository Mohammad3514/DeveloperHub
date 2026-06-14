/**
 * user.js – Protected User API Routes
 *
 * All routes require a valid JWT (via authMiddleware).
 * Admin-only routes additionally require requireRole('admin').
 *
 * GET    /api/profile          – Get own profile
 * PUT    /api/profile          – Update own profile
 * GET    /api/users            – List all users (admin only)
 * DELETE /api/users/:id        – Delete a user (admin only)
 */

const express  = require('express');
const User     = require('../models/User');
const logger   = require('../utils/logger');
const { authMiddleware, requireRole } = require('../middleware/auth');
const { validateProfileUpdate }       = require('../middleware/validate');

const router = express.Router();

// ─── GET /api/profile ─────────────────────────────────────────────
// Returns the authenticated user's profile data.
// req.user is populated by authMiddleware from the JWT payload.
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    logger.info(`Profile accessed by user: ${req.user.email}`);
    return res.status(200).json({ user });
  } catch (err) {
    logger.error(`Profile fetch error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred' });
  }
});

// ─── PUT /api/profile ─────────────────────────────────────────────
// Allows a user to update their own name or bio.
// validateProfileUpdate sanitizes and validates the body first.
router.put('/profile', authMiddleware, validateProfileUpdate, async (req, res) => {
  try {
    const updates = req.sanitized; // only contains validated & escaped fields

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`Profile updated by user: ${req.user.email}`);
    return res.status(200).json({ message: 'Profile updated', user });
  } catch (err) {
    logger.error(`Profile update error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred' });
  }
});

// ─── GET /api/users ───────────────────────────────────────────────
// Admin only – returns list of all users (no passwords).
router.get('/users', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    logger.info(`User list accessed by admin: ${req.user.email}`);
    return res.status(200).json({ count: users.length, users });
  } catch (err) {
    logger.error(`User list fetch error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred' });
  }
});

// ─── DELETE /api/users/:id ────────────────────────────────────────
// Admin only – deletes a user by ID.
router.delete('/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent admin from deleting themselves
    if (id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account via this endpoint' });
    }

    const deleted = await User.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.warn(`User deleted: ${deleted.email} by admin: ${req.user.email}`);
    return res.status(200).json({ message: 'User deleted successfully' });
  } catch (err) {
    logger.error(`User delete error: ${err.message}`);
    return res.status(500).json({ error: 'An error occurred' });
  }
});

module.exports = router;
