// scripts/fixAdmin.js
require('dotenv').config({ path: '../.env' });
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Define schema (copied from your app)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    accountNumber: { type: String, unique: true, sparse: true },
    dateOfBirth: { type: Date, required: true },
    gender: { type: String, required: true, enum: ['male', 'female', 'other', 'prefer-not'] },
    country: { type: String, required: true, enum: ['United States', 'United Kingdom'] },
    addressLine1: { type: String, required: true },
    addressLine2: { type: String, default: '' },
    city: { type: String, required: true },
    state: { type: String },
    zipCode: { type: String, required: true },
    ssn: { type: String, default: null },
    isAdmin: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    hasCard: { type: Boolean, default: false },
    cardRequested: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

async function fixAdmin() {
    try {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/bankapp');
        console.log('✅ Connected to MongoDB');

        // Delete any existing admin with that email
        await User.deleteOne({ email: 'admin@saxonbank.com' });
        console.log('🗑️ Old admin deleted (if existed)');

        // Hash password
        const hashedPassword = await bcrypt.hash('admin123', 10);

        // Create new admin with ALL required fields
        const admin = new User({
            name: 'Admin',
            email: 'admin@saxonbank.com',
            password: hashedPassword,
            balance: 10000,
            accountNumber: 'ADM' + Math.floor(10000000 + Math.random() * 90000000),
            dateOfBirth: new Date('1980-01-01'),
            gender: 'male',
            country: 'United States',
            addressLine1: '123 Admin St',
            city: 'New York',
            state: 'NY',
            zipCode: '10001',
            isAdmin: true,
            isVerified: true,
            hasCard: false,
            cardRequested: false
        });

        await admin.save();
        console.log('✅ New admin created successfully!');
        console.log('📧 Email: admin@saxonbank.com');
        console.log('🔑 Password: admin123');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

fixAdmin();
