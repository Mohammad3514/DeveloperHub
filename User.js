/**
 * User.js – Mongoose User model
 *
 * Security features:
 *  - Password field excluded from default queries (select: false)
 *  - Pre-save hook hashes password with bcrypt (saltRounds=10)
 *  - comparePassword() instance method for safe comparison
 */

const mongoose = require('mongoose');
const bcrypt   = require('bcrypt');

const SALT_ROUNDS = 10;

const userSchema = new mongoose.Schema(
  {
    name: {
      type:     String,
      required: [true, 'Name is required'],
      trim:     true,
      maxlength: [100, 'Name cannot exceed 100 characters'],
    },
    email: {
      type:      String,
      required:  [true, 'Email is required'],
      unique:    true,
      lowercase: true,
      trim:      true,
      maxlength: [255, 'Email cannot exceed 255 characters'],
    },
    password: {
      type:     String,
      required: [true, 'Password is required'],
      select:   false, // never returned in queries unless explicitly requested
      minlength: [8, 'Password must be at least 8 characters'],
    },
    role: {
      type:    String,
      enum:    ['user', 'admin'],
      default: 'user',
    },
    createdAt: {
      type:    Date,
      default: Date.now,
    },
    lastLogin: {
      type: Date,
    },
  },
  {
    // Remove __v from responses
    versionKey: false,
    // Strip password from toJSON output
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        return ret;
      },
    },
  }
);

// ─── Pre-save: Hash password before storing ──────────────────────
userSchema.pre('save', async function (next) {
  // Only hash if password field was modified (or is new)
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    next();
  } catch (err) {
    next(err);
  }
});

// ─── Instance method: Compare plain password with hash ───────────
userSchema.methods.comparePassword = async function (plainPassword) {
  // 'this.password' is excluded by select:false, so we must explicitly
  // call .select('+password') before calling this method.
  return bcrypt.compare(plainPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
