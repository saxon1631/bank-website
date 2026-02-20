require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const nodemailer = require("nodemailer");

// ===== File upload dependencies =====
const multer = require('multer');
const fs = require('fs');

const app = express();

// ========== FILE UPLOAD CONFIGURATION ==========
// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'public/uploads/kyc');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/kyc/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only images and PDFs are allowed'));
        }
    }
});

// ========== MIDDLEWARE ==========
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "saxonbank_secret_key",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false,
            maxAge: 24 * 60 * 60 * 1000,
        },
    })
);

// ========== EMAIL TRANSPORTER (Zoho) ==========
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.zoho.com',
    port: process.env.EMAIL_PORT || 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

// ========== DATABASE ==========
mongoose
    .connect(process.env.MONGO_URI || "mongodb://localhost:27017/bankapp")
    .then(() => console.log("✅ MongoDB Connected Successfully"))
    .catch((err) => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

// ========== MODELS ==========
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    accountNumber: { type: String, unique: true, sparse: true },

    // Personal Details
    dateOfBirth: { type: Date, required: true },
    gender: { type: String, required: true, enum: ['male', 'female', 'other', 'prefer-not'] },
    country: { type: String, required: true, enum: ['United States', 'United Kingdom'] },

    // Address fields
    addressLine1: { type: String, required: true },
    addressLine2: { type: String, default: '' },
    city: { type: String, required: true },
    state: { type: String },
    zipCode: { type: String, required: true },

    // SSN (only for US users)
    ssn: { type: String, default: null },

    // Card Fields
    hasCard: { type: Boolean, default: false },
    cardNumber: { type: String, default: null },
    cardExpiry: { type: String, default: null },
    cardCVV: { type: String, default: null },
    cardRequested: { type: Boolean, default: false },

    // KYC Verification Fields
    isVerified: { type: Boolean, default: false },
    kycPending: { type: Boolean, default: false },
    kycProgress: { type: Number, default: 0, min: 0, max: 100 },
    idVerified: { type: Boolean, default: false },
    addressVerified: { type: Boolean, default: false },
    selfieVerified: { type: Boolean, default: false },
    kycDocuments: [{
        type: { type: String, enum: ['id', 'address', 'selfie'] },
        url: String,
        uploadedAt: { type: Date, default: Date.now },
        status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
    }],

    // NEW: Dark Mode Preference
    darkMode: { type: Boolean, default: false },

    // Notification Preferences
    emailNotifications: { type: Boolean, default: true },
    smsNotifications: { type: Boolean, default: false },
    pushNotifications: { type: Boolean, default: true },

    // Security Settings
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, default: null },
    loginAlerts: { type: Boolean, default: true },

    // Transaction Limits
    dailyLimit: { type: Number, default: 5000 },
    weeklyLimit: { type: Number, default: 25000 },
    monthlyLimit: { type: Number, default: 100000 },

    // Admin & Metadata
    isAdmin: { type: Boolean, default: false },
    lastLogin: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },

    // Password Reset Fields
    resetToken: { type: String, default: null },
    resetTokenExpiry: { type: Date, default: null },

    // NEW: Referral Fields
    referralCode: { type: String, unique: true, sparse: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    referralEarnings: { type: Number, default: 0 },
    referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
});

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, enum: ["deposit", "withdrawal", "transfer", "payment"], required: true },
    amount: { type: Number, required: true },
    description: String,
    toAccount: String,
    toUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    fromAccount: String,
    fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    status: { type: String, enum: ["pending", "completed", "failed", "rejected"], default: "completed" },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    processedDate: { type: Date },
    date: { type: Date, default: Date.now },
});

const cardRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    requestDate: { type: Date, default: Date.now },
    processedDate: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const kycRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    documents: [{
        type: { type: String, enum: ['id', 'address', 'selfie'] },
        url: String,
        filename: String
    }],
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    submittedAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    notes: String
});

// ========== NEW: BILL PAYMENT MODELS ==========
const billerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, enum: ['utility', 'credit card', 'loan', 'internet', 'phone', 'other'], required: true },
    accountNumber: { type: String, required: true, unique: true },
    description: String,
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const billPaymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    billerId: { type: mongoose.Schema.Types.ObjectId, ref: "Biller", required: true },
    amount: { type: Number, required: true },
    reference: { type: String, required: true, unique: true },
    status: { type: String, enum: ["pending", "completed", "failed"], default: "completed" },
    paymentDate: { type: Date, default: Date.now },
    processedDate: { type: Date },
    description: String
});

// ========== NEW: LOAN MODELS ==========
const loanSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    loanType: { type: String, enum: ['personal', 'car', 'education', 'home', 'business', 'construction'], required: true },
    amount: { type: Number, required: true },
    term: { type: Number, required: true }, // in years
    purpose: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    interestRate: { type: Number },
    monthlyPayment: { type: Number },
    appliedDate: { type: Date, default: Date.now },
    processedDate: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    notes: String
});

// ========== NEW: REFERRAL MODEL ==========
const referralSchema = new mongoose.Schema({
    referrerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    referredId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
    rewardAmount: { type: Number, default: 50 },
    referredDate: { type: Date, default: Date.now },
    completedDate: { type: Date }
});

// ========== NEW: NOTIFICATION MODEL ==========
const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, enum: ['deposit', 'transfer', 'payment', 'security', 'card', 'loan', 'referral'], required: true },
    title: String,
    message: String,
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const CardRequest = mongoose.model("CardRequest", cardRequestSchema);
const KycRequest = mongoose.model("KycRequest", kycRequestSchema);
const Biller = mongoose.model("Biller", billerSchema);
const BillPayment = mongoose.model("BillPayment", billPaymentSchema);
const Loan = mongoose.model("Loan", loanSchema);
const Referral = mongoose.model("Referral", referralSchema);
const Notification = mongoose.model("Notification", notificationSchema);

// ========== AUTH MIDDLEWARE ==========
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.redirect("/dashboard");
    }
    next();
};

// ========== HELPER FUNCTIONS ==========
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

// Generate unique referral code
function generateReferralCode(name) {
    const prefix = name.substring(0, 3).toUpperCase();
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `${prefix}${random}`;
}

// ========== ROUTES ==========
// Home page (landing)
app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/dashboard");
    }
    res.render("index", {
        title: "Saxon Bank – Modern Banking for Everyone"
    });
});

// Login Page
app.get("/login", (req, res) => {
    if (req.session.userId) return res.redirect("/dashboard");
    res.render("login", {
        title: "Login | Saxon Bank",
        error: req.query.error || null,
        success: req.query.success || null,
    });
});

// Login POST
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.render("login", {
                title: "Login | Saxon Bank",
                error: "Invalid email or password",
            });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.render("login", {
                title: "Login | Saxon Bank",
                error: "Invalid email or password",
            });
        }

        user.lastLogin = new Date();
        await user.save();

        req.session.userId = user._id;
        req.session.isAdmin = user.isAdmin || false;
        res.redirect("/dashboard");
    } catch (error) {
        console.error(error);
        res.render("login", {
            title: "Login | Saxon Bank",
            error: "Something went wrong. Please try again.",
        });
    }
});

// Register Page
app.get("/register", (req, res) => {
    res.render("register", {
        title: "Register | Saxon Bank",
        error: req.query.error || null,
        success: req.query.success || null,
    });
});

// Register POST (updated with referral code)
app.post("/register", async (req, res) => {
    try {
        const {
            email, password, confirmPassword,
            name, dateOfBirth, gender, country,
            usStreet, usApt, usCity, usState, usZip,
            ukStreet, ukApt, ukCity, ukCounty, ukPostcode,
            ssn, referralCode
        } = req.body;

        if (password !== confirmPassword) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "Passwords do not match",
                success: null
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "Email already registered",
                success: null
            });
        }

        const birthDate = new Date(dateOfBirth);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        const m = today.getMonth() - birthDate.getMonth();
        if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) age--;
        if (age < 18) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "You must be at least 18 years old",
                success: null
            });
        }

        if (!['United States', 'United Kingdom'].includes(country)) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "Registration is only available to residents of the United States or United Kingdom",
                success: null
            });
        }

        let addressLine1, addressLine2, city, state, zipCode;
        if (country === 'United States') {
            addressLine1 = usStreet;
            addressLine2 = usApt || '';
            city = usCity;
            state = usState;
            zipCode = usZip;
        } else {
            addressLine1 = ukStreet;
            addressLine2 = ukApt || '';
            city = ukCity;
            state = ukCounty || '';
            zipCode = ukPostcode;
        }

        if (!addressLine1 || !city || !zipCode) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "Please fill in all required address fields",
                success: null
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const accountNumber = Math.floor(1000000000 + Math.random() * 9000000000).toString();
        const userReferralCode = generateReferralCode(name);

        const userData = {
            name,
            email,
            password: hashedPassword,
            accountNumber,
            dateOfBirth: new Date(dateOfBirth),
            gender,
            country,
            addressLine1,
            addressLine2,
            city,
            state,
            zipCode,
            hasCard: false,
            cardRequested: false,
            referralCode: userReferralCode
        };

        if (country === 'United States' && ssn) {
            userData.ssn = ssn;
        }

        const user = new User(userData);
        await user.save();

        // Handle referral if provided
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                const referral = new Referral({
                    referrerId: referrer._id,
                    referredId: user._id,
                    status: 'pending'
                });
                await referral.save();

                referrer.referrals.push(user._id);
                await referrer.save();

                // Create notification for referrer
                const notification = new Notification({
                    userId: referrer._id,
                    type: 'referral',
                    title: 'New Referral!',
                    message: `${name} signed up using your referral link. They'll need to complete their first transaction for you to earn $50.`
                });
                await notification.save();
            }
        }

        res.redirect("/login?success=Registration successful! Please login.");
    } catch (error) {
        console.error(error);
        res.render("register", {
            title: "Register | Saxon Bank",
            error: "Registration failed. Please try again.",
            success: null
        });
    }
});

// ========== PASSWORD RESET ROUTES ==========
app.get("/forgot-password", (req, res) => {
    res.render("forgot-password", {
        title: "Forgot Password | Saxon Bank",
        error: req.query.error || null,
        success: req.query.success || null
    });
});

app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.redirect("/forgot-password?success=If that email exists, we'll send reset instructions");
        }

        const resetToken = Math.random().toString(36).slice(-8);
        const expiry = Date.now() + 3600000;

        user.resetToken = resetToken;
        user.resetTokenExpiry = expiry;
        await user.save();

        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;

        await transporter.sendMail({
            from: `"Saxon Bank" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <h2>Reset Your Password</h2>
                <p>You requested a password reset. Click the link below to set a new password. This link expires in 1 hour.</p>
                <p><a href="${resetLink}">${resetLink}</a></p>
                <p>If you didn't request this, please ignore this email.</p>
                <br>
                <p>– Saxon Bank Team</p>
            `
        });

        console.log(`🔐 Password reset email sent to: ${email}`);
        res.redirect("/forgot-password?success=Reset instructions sent to your email");
    } catch (error) {
        console.error("Password reset error:", error);
        res.redirect("/forgot-password?error=Something went wrong. Please try again.");
    }
});

app.get("/reset-password", (req, res) => {
    const { token, email } = req.query;
    if (!token || !email) {
        return res.redirect("/forgot-password?error=Invalid reset link");
    }
    res.render("reset-password", {
        title: "Reset Password | Saxon Bank",
        token,
        email,
        error: null,
        success: null,
        valid: true
    });
});

app.post("/reset-password", async (req, res) => {
    try {
        const { email, token, password, confirm } = req.body;
        if (password !== confirm) {
            return res.render("reset-password", {
                title: "Reset Password | Saxon Bank",
                token,
                email,
                error: "Passwords do not match",
                success: null,
                valid: true
            });
        }
        const user = await User.findOne({ email, resetToken: token });
        if (!user || user.resetTokenExpiry < Date.now()) {
            return res.render("reset-password", {
                title: "Reset Password | Saxon Bank",
                token,
                email,
                error: "Invalid or expired reset link",
                success: null,
                valid: true
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        res.render("reset-password", {
            title: "Reset Password | Saxon Bank",
            token: null,
            email: null,
            error: null,
            success: "Password reset successfully! You can now login.",
            valid: false
        });
    } catch (error) {
        console.error(error);
        res.redirect("/forgot-password?error=Something went wrong");
    }
});

// ========== PROFILE & SETTINGS ROUTES ==========
app.get("/profile", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("profile", {
            title: "Profile | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Profile error:", error);
        res.redirect("/dashboard");
    }
});

app.post("/profile/update", requireAuth, async (req, res) => {
    try {
        const { name, phone, address, dateOfBirth } = req.body;
        await User.findByIdAndUpdate(req.session.userId, {
            name,
            phone,
            address,
            dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null
        });
        res.redirect("/profile?success=Profile updated successfully");
    } catch (error) {
        console.error("Profile update error:", error);
        res.redirect("/profile?error=Failed to update profile");
    }
});

app.get("/settings", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("settings", {
            title: "Settings | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Settings error:", error);
        res.redirect("/dashboard");
    }
});

app.post("/settings/update", requireAuth, async (req, res) => {
    try {
        const { emailNotifications, smsNotifications, pushNotifications, loginAlerts } = req.body;
        await User.findByIdAndUpdate(req.session.userId, {
            emailNotifications: emailNotifications === 'on',
            smsNotifications: smsNotifications === 'on',
            pushNotifications: pushNotifications === 'on',
            loginAlerts: loginAlerts === 'on'
        });
        res.redirect("/settings?success=Settings updated successfully");
    } catch (error) {
        console.error("Settings update error:", error);
        res.redirect("/settings?error=Failed to update settings");
    }
});

// Dark Mode API
app.post("/api/user/darkmode", requireAuth, async (req, res) => {
    try {
        const { darkMode } = req.body;
        await User.findByIdAndUpdate(req.session.userId, { darkMode });
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false });
    }
});

app.get("/privacy", requireAuth, async (req, res) => {
    res.render("privacy", {
        title: "Privacy & Security | Saxon Bank",
        success: req.query.success || null,
        error: req.query.error || null
    });
});

app.get("/notifications", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const notifications = await Notification.find({ userId: user._id }).sort({ createdAt: -1 });
        res.render("notifications", {
            title: "Notifications | Saxon Bank",
            user,
            notifications,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Notifications error:", error);
        res.redirect("/dashboard");
    }
});

app.get("/limits", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("limits", {
            title: "Transaction Limits | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Limits error:", error);
        res.redirect("/dashboard");
    }
});

// ========== STATEMENT ROUTE ==========
app.get("/statement", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        res.render("statement", {
            title: "Account Statement | Saxon Bank",
            user,
            transactions,
            formatCurrency
        });
    } catch (error) {
        console.error("Statement error:", error);
        res.redirect("/dashboard");
    }
});

// ========== INSIGHTS ROUTE ==========
app.get("/insights", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        
        // Calculate spending by category
        const categories = {};
        transactions.forEach(t => {
            if (t.type !== 'deposit') {
                const cat = t.type === 'payment' ? 'Bill Payments' : 
                           t.type === 'transfer' ? 'Transfers' : 'Other';
                categories[cat] = (categories[cat] || 0) + t.amount;
            }
        });

        const totalSpent = transactions.filter(t => t.type !== 'deposit').reduce((sum, t) => sum + t.amount, 0);
        
        res.render("insights", {
            title: "Spending Insights | Saxon Bank",
            user,
            transactions,
            categories,
            totalSpent,
            formatCurrency
        });
    } catch (error) {
        console.error("Insights error:", error);
        res.redirect("/dashboard");
    }
});

// API for insights data
app.get("/api/spending", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        
        const summary = {
            totalSpent: transactions.filter(t => t.type !== 'deposit').reduce((sum, t) => sum + t.amount, 0),
            avgPerDay: 0,
            topCategory: 'N/A',
            savingsRate: 0
        };

        const chart = {
            labels: [],
            values: []
        };

        const monthly = [];

        res.json({ summary, chart, monthly });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== BILL PAYMENT ROUTES ==========
app.get("/billers", requireAuth, async (req, res) => {
    try {
        const billers = await Biller.find({ isActive: true }).sort({ category: 1, name: 1 });
        const user = await User.findById(req.session.userId);
        const payments = await BillPayment.find({ userId: user._id })
            .populate("billerId")
            .sort({ paymentDate: -1 })
            .limit(10);
        
        res.render("billers", {
            title: "Bill Payment | Saxon Bank",
            user,
            billers,
            payments,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Billers error:", error);
        res.redirect("/dashboard");
    }
});

app.post("/billers/pay", requireAuth, async (req, res) => {
    try {
        const { billerId, amount, description } = req.body;
        const user = await User.findById(req.session.userId);
        const biller = await Biller.findById(billerId);
        
        if (!biller) {
            return res.redirect("/billers?error=Biller not found");
        }
        
        if (user.balance < Number(amount)) {
            return res.redirect("/billers?error=Insufficient funds");
        }
        
        const reference = 'BILL-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        
        user.balance -= Number(amount);
        await user.save();
        
        const payment = new BillPayment({
            userId: user._id,
            billerId: biller._id,
            amount: Number(amount),
            reference: reference,
            status: "completed",
            processedDate: new Date(),
            description: description || `Payment to ${biller.name}`
        });
        await payment.save();
        
        const transaction = new Transaction({
            userId: user._id,
            type: "payment",
            amount: Number(amount),
            description: `Bill payment to ${biller.name}`,
            status: "completed"
        });
        await transaction.save();

        // Create notification
        const notification = new Notification({
            userId: user._id,
            type: 'payment',
            title: 'Bill Payment Successful',
            message: `Your payment of ${formatCurrency(amount)} to ${biller.name} was successful. Reference: ${reference}`
        });
        await notification.save();
        
        res.redirect(`/billers?success=Payment of ${formatCurrency(amount)} to ${biller.name} completed successfully.`);
    } catch (error) {
        console.error("Payment error:", error);
        res.redirect("/billers?error=Payment failed: " + error.message);
    }
});

app.get("/billers/history", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const payments = await BillPayment.find({ userId: user._id })
            .populate("billerId")
            .sort({ paymentDate: -1 });
        
        res.render("bill-history", {
            title: "Payment History | Saxon Bank",
            user,
            payments,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Payment history error:", error);
        res.redirect("/dashboard");
    }
});

// ========== LOAN ROUTES ==========
app.get("/loans", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const loans = await Loan.find({ userId: user._id }).sort({ appliedDate: -1 });
        
        res.render("loans", {
            title: "Loan Applications | Saxon Bank",
            user,
            loans,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Loans error:", error);
        res.redirect("/dashboard");
    }
});

app.post("/loans/apply", requireAuth, async (req, res) => {
    try {
        const { loanType, amount, term, purpose } = req.body;
        const user = await User.findById(req.session.userId);
        
        const loan = new Loan({
            userId: user._id,
            loanType,
            amount: Number(amount),
            term: Number(term),
            purpose,
            status: 'pending'
        });
        
        await loan.save();

        // Create notification
        const notification = new Notification({
            userId: user._id,
            type: 'loan',
            title: 'Loan Application Submitted',
            message: `Your ${loanType} loan application for ${formatCurrency(amount)} has been submitted for review.`
        });
        await notification.save();
        
        res.redirect("/loans?success=Loan application submitted successfully!");
    } catch (error) {
        console.error("Loan application error:", error);
        res.redirect("/loans?error=Failed to submit application");
    }
});

// ========== REFERRAL ROUTES ==========
app.get("/referrals", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).populate('referrals');
        const referralStats = await Referral.find({ referrerId: user._id });
        
        const totalReferrals = referralStats.length;
        const completedReferrals = referralStats.filter(r => r.status === 'completed').length;
        const pendingReferrals = totalReferrals - completedReferrals;
        const earned = referralStats.filter(r => r.status === 'completed').reduce((sum, r) => sum + r.rewardAmount, 0);
        
        res.render("referrals", {
            title: "Referral Program | Saxon Bank",
            user,
            referrals: referralStats,
            totalReferrals,
            completedReferrals,
            pendingReferrals,
            earned,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Referrals error:", error);
        res.redirect("/dashboard");
    }
});

// ========== CHAT SUPPORT ROUTE ==========
app.get("/chat", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("chat", {
            title: "Chat Support | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Chat error:", error);
        res.redirect("/dashboard");
    }
});

// ========== MULTI-CURRENCY ROUTE ==========
app.get("/currency", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("currency", {
            title: "Multi-Currency | Saxon Bank",
            user,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Currency error:", error);
        res.redirect("/dashboard");
    }
});

// ========== KYC VERIFICATION ROUTES ==========
app.get("/kyc", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const kycRequest = await KycRequest.findOne({ userId: user._id, status: "pending" });

        res.render("kyc", {
            title: "Identity Verification | Saxon Bank",
            user,
            kycRequest,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("KYC page error:", error);
        res.redirect("/dashboard");
    }
});

app.post("/kyc/submit", requireAuth, upload.fields([
    { name: 'idDocument', maxCount: 1 },
    { name: 'addressDocument', maxCount: 1 },
    { name: 'selfieDocument', maxCount: 1 }
]), async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        if (user.isVerified) {
            return res.redirect("/kyc?error=You are already verified");
        }
        
        const existingRequest = await KycRequest.findOne({ 
            userId: user._id, 
            status: "pending" 
        });
        
        if (existingRequest) {
            return res.redirect("/kyc?error=You already have a pending verification request");
        }
        
        const documents = [];
        
        if (req.files['idDocument']) {
            documents.push({
                type: 'id',
                url: '/uploads/kyc/' + req.files['idDocument'][0].filename,
                filename: req.files['idDocument'][0].originalname
            });
        }
        
        if (req.files['addressDocument']) {
            documents.push({
                type: 'address',
                url: '/uploads/kyc/' + req.files['addressDocument'][0].filename,
                filename: req.files['addressDocument'][0].originalname
            });
        }
        
        if (req.files['selfieDocument']) {
            documents.push({
                type: 'selfie',
                url: '/uploads/kyc/' + req.files['selfieDocument'][0].filename,
                filename: req.files['selfieDocument'][0].originalname
            });
        }
        
        const kycRequest = new KycRequest({
            userId: user._id,
            documents: documents,
            status: "pending",
            submittedAt: new Date()
        });
        
        await kycRequest.save();
        
        user.kycPending = true;
        user.kycProgress = 33;
        await user.save();

        // Create notification
        const notification = new Notification({
            userId: user._id,
            type: 'security',
            title: 'KYC Submitted',
            message: 'Your KYC documents have been submitted for verification. We\'ll notify you once reviewed.'
        });
        await notification.save();
        
        console.log(`✅ KYC submitted for user: ${user.email} with ${documents.length} documents`);
        res.redirect("/kyc?success=Documents submitted successfully! We'll review them within 24 hours.");
        
    } catch (error) {
        console.error("KYC submission error:", error);
        res.redirect("/kyc?error=Failed to submit documents: " + error.message);
    }
});

// ========== DASHBOARD ==========
app.get("/dashboard", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const transactions = await Transaction.find({ userId: user._id })
            .sort({ date: -1 })
            .limit(10);
        res.render("dashboard", {
            title: "Dashboard | Saxon Bank",
            user,
            transactions,
            formatCurrency
        });
    } catch (error) {
        console.error(error);
        res.redirect("/login");
    }
});

// Deposit Page
app.get("/deposit", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("deposit", {
            title: "Deposit | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Deposit page error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/deposit", requireAuth, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.session.userId);

        user.balance += Number(amount);
        await user.save();

        const transaction = new Transaction({
            userId: user._id,
            type: "deposit",
            amount: Number(amount),
            description: "Deposit to account",
            status: "completed"
        });
        await transaction.save();

        res.redirect("/dashboard?success=Deposit successful");
    } catch (error) {
        console.error("Deposit error:", error);
        res.redirect("/deposit?error=Deposit failed");
    }
});

// Transfer Page
app.get("/transfer", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("transfer", {
            title: "Transfer | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null,
        });
    } catch (error) {
        console.error("Transfer page error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/transfer", requireAuth, async (req, res) => {
    try {
        const { toAccount, amount, description } = req.body;
        const sender = await User.findById(req.session.userId);
        const recipient = await User.findOne({ accountNumber: toAccount });

        if (!recipient) {
            return res.redirect("/transfer?error=Recipient account not found");
        }

        if (sender.balance < Number(amount)) {
            return res.redirect("/transfer?error=Insufficient funds");
        }

        sender.balance -= Number(amount);
        await sender.save();

        const transaction = new Transaction({
            userId: sender._id,
            type: "transfer",
            amount: Number(amount),
            description: description || `Transfer to account ${toAccount}`,
            toAccount: toAccount,
            toUserId: recipient._id,
            fromAccount: sender.accountNumber,
            fromUserId: sender._id,
            status: "pending"
        });
        await transaction.save();

        res.redirect(`/transfer?success=Transfer initiated! Amount $${amount} debited from your account. Pending admin approval.`);
    } catch (error) {
        console.error("Transfer error:", error);
        res.redirect("/transfer?error=Transfer failed");
    }
});

// Transactions History
app.get("/transactions", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        res.render("transactions", {
            title: "Transactions | Saxon Bank",
            user,
            transactions,
            formatCurrency
        });
    } catch (error) {
        console.error("Transactions page error:", error);
        res.status(500).send("Server error");
    }
});

// Card Page - Apply for Card
app.get("/card", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const existingRequest = await CardRequest.findOne({
            userId: user._id,
            status: "pending"
        });

        res.render("card", {
            title: "Card Services | Saxon Bank",
            user,
            hasCard: user.hasCard,
            cardRequested: user.cardRequested,
            pendingRequest: existingRequest ? true : false,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Card page error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/card/apply", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);

        if (user.hasCard) {
            return res.redirect("/card?error=You already have a card");
        }

        if (user.cardRequested) {
            return res.redirect("/card?error=You already have a pending request");
        }

        const cardRequest = new CardRequest({
            userId: user._id,
            status: "pending"
        });
        await cardRequest.save();

        user.cardRequested = true;
        await user.save();

        res.redirect("/card?success=Your card request has been submitted! We will review and contact you within 2-3 business days.");
    } catch (error) {
        console.error("Card application error:", error);
        res.redirect("/card?error=Something went wrong. Please try again.");
    }
});

// ========== ADMIN ROUTES ==========
app.get("/admin", requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const pendingTransfers = await Transaction.find({
            type: "transfer",
            status: "pending"
        }).populate("fromUserId toUserId");
        const pendingCards = await CardRequest.find({
            status: "pending"
        }).populate("userId");
        const pendingKyc = await KycRequest.find({
            status: "pending"
        }).populate("userId");
        const pendingLoans = await Loan.find({ status: "pending" }).populate("userId");
        const billers = await Biller.find({});

        res.render("admin/dashboard", {
            title: "Admin Dashboard | Saxon Bank",
            users: users,
            pendingTransfers: pendingTransfers,
            pendingCards: pendingCards,
            pendingKyc: pendingKyc,
            pendingLoans: pendingLoans,
            billers: billers,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin dashboard error:", error);
        res.status(500).send("Server error");
    }
});

// ========== ADMIN BILLER MANAGEMENT ==========
app.get("/admin/billers", requireAuth, requireAdmin, async (req, res) => {
    try {
        const billers = await Biller.find().sort({ category: 1, name: 1 });
        res.render("admin/billers", {
            title: "Manage Billers | Admin",
            billers,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin billers error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/admin/billers/add", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { name, category, accountNumber, description } = req.body;
        
        const existingBiller = await Biller.findOne({ accountNumber });
        if (existingBiller) {
            return res.redirect("/admin/billers?error=Biller with this account number already exists");
        }
        
        const biller = new Biller({
            name,
            category,
            accountNumber,
            description,
            isActive: true
        });
        
        await biller.save();
        res.redirect("/admin/billers?success=Biller added successfully");
    } catch (error) {
        console.error("Add biller error:", error);
        res.redirect("/admin/billers?error=Failed to add biller");
    }
});

app.post("/admin/billers/:id/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
        const biller = await Biller.findById(req.params.id);
        biller.isActive = !biller.isActive;
        await biller.save();
        
        res.redirect("/admin/billers?success=Biller status updated");
    } catch (error) {
        console.error("Toggle biller error:", error);
        res.redirect("/admin/billers?error=Failed to update biller");
    }
});

app.post("/admin/billers/:id/delete", requireAuth, requireAdmin, async (req, res) => {
    try {
        await Biller.findByIdAndDelete(req.params.id);
        res.redirect("/admin/billers?success=Biller deleted");
    } catch (error) {
        console.error("Delete biller error:", error);
        res.redirect("/admin/billers?error=Failed to delete biller");
    }
});

// ========== ADMIN LOAN MANAGEMENT ==========
app.get("/admin/loans", requireAuth, requireAdmin, async (req, res) => {
    try {
        const pendingLoans = await Loan.find({ status: "pending" }).populate("userId");
        const approvedLoans = await Loan.find({ status: "approved" }).populate("userId").limit(50);
        const rejectedLoans = await Loan.find({ status: "rejected" }).populate("userId").limit(50);
        
        res.render("admin/loans", {
            title: "Loan Applications | Admin",
            pendingLoans,
            approvedLoans,
            rejectedLoans,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin loans error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/admin/loans/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const loan = await Loan.findById(req.params.id);
        const user = await User.findById(loan.userId);
        
        // Calculate monthly payment (simple interest)
        const monthlyRate = 0.05 / 12; // 5% annual rate example
        const months = loan.term * 12;
        const monthlyPayment = (loan.amount * monthlyRate * Math.pow(1 + monthlyRate, months)) / 
                              (Math.pow(1 + monthlyRate, months) - 1);
        
        loan.status = "approved";
        loan.interestRate = 5.0;
        loan.monthlyPayment = monthlyPayment;
        loan.processedDate = new Date();
        loan.processedBy = req.session.userId;
        await loan.save();

        // Add to user balance
        user.balance += loan.amount;
        await user.save();

        // Create transaction
        const transaction = new Transaction({
            userId: user._id,
            type: "deposit",
            amount: loan.amount,
            description: `${loan.loanType} loan approved - funds disbursed`,
            status: "completed"
        });
        await transaction.save();

        // Create notification
        const notification = new Notification({
            userId: user._id,
            type: 'loan',
            title: 'Loan Approved!',
            message: `Your ${loan.loanType} loan of ${formatCurrency(loan.amount)} has been approved and funds have been added to your account.`
        });
        await notification.save();
        
        res.redirect("/admin/loans?success=Loan approved and funds disbursed");
    } catch (error) {
        console.error("Loan approval error:", error);
        res.redirect("/admin/loans?error=Failed to approve loan");
    }
});

app.post("/admin/loans/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    try {
        const loan = await Loan.findById(req.params.id);
        
        loan.status = "rejected";
        loan.processedDate = new Date();
        loan.processedBy = req.session.userId;
        loan.notes = req.body.notes || "Application rejected";
        await loan.save();

        // Create notification
        const notification = new Notification({
            userId: loan.userId,
            type: 'loan',
            title: 'Loan Application Update',
            message: `Your ${loan.loanType} loan application has been reviewed and was not approved at this time.`
        });
        await notification.save();
        
        res.redirect("/admin/loans?success=Loan rejected");
    } catch (error) {
        console.error("Loan rejection error:", error);
        res.redirect("/admin/loans?error=Failed to reject loan");
    }
});

// ========== ADMIN KYC MANAGEMENT ==========
app.get("/admin/kyc", requireAuth, requireAdmin, async (req, res) => {
    try {
        const pendingRequests = await KycRequest.find({ status: "pending" })
            .populate("userId")
            .sort({ submittedAt: -1 });

        const approvedRequests = await KycRequest.find({ status: "approved" })
            .populate("userId")
            .sort({ processedAt: -1 })
            .limit(50);

        const rejectedRequests = await KycRequest.find({ status: "rejected" })
            .populate("userId")
            .sort({ processedAt: -1 })
            .limit(50);

        res.render("admin/kyc", {
            title: "KYC Requests | Admin",
            pendingRequests: pendingRequests || [],
            approvedRequests: approvedRequests || [],
            rejectedRequests: rejectedRequests || [],
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin KYC error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/admin/kyc/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const kycRequest = await KycRequest.findById(req.params.id);

        kycRequest.status = "approved";
        kycRequest.processedAt = new Date();
        kycRequest.processedBy = req.session.userId;
        await kycRequest.save();

        await User.findByIdAndUpdate(kycRequest.userId, {
            isVerified: true,
            kycPending: false,
            kycProgress: 100,
            idVerified: true,
            addressVerified: true,
            selfieVerified: true
        });

        // Create notification
        const notification = new Notification({
            userId: kycRequest.userId,
            type: 'security',
            title: 'KYC Verified!',
            message: 'Your identity has been successfully verified. You now have full access to all features.'
        });
        await notification.save();

        res.redirect("/admin/kyc?success=KYC approved successfully");
    } catch (error) {
        console.error("KYC approval error:", error);
        res.redirect("/admin/kyc?error=Failed to approve KYC");
    }
});

app.post("/admin/kyc/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    try {
        const kycRequest = await KycRequest.findById(req.params.id);

        kycRequest.status = "rejected";
        kycRequest.processedAt = new Date();
        kycRequest.processedBy = req.session.userId;
        kycRequest.notes = req.body.notes || "Documents rejected";
        await kycRequest.save();

        await User.findByIdAndUpdate(kycRequest.userId, {
            kycPending: false,
            kycProgress: 0
        });

        // Create notification
        const notification = new Notification({
            userId: kycRequest.userId,
            type: 'security',
            title: 'KYC Update',
            message: `Your KYC documents were not approved. Reason: ${kycRequest.notes}. Please resubmit with clearer documents.`
        });
        await notification.save();

        res.redirect("/admin/kyc?success=KYC rejected");
    } catch (error) {
        console.error("KYC rejection error:", error);
        res.redirect("/admin/kyc?error=Failed to reject KYC");
    }
});

// ========== ADMIN USER MANAGEMENT ==========
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}).sort({ createdAt: -1 });
        res.render("admin/users", {
            title: "User Management | Admin",
            users,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin users error:", error);
        res.status(500).send("Server error");
    }
});

app.get("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        const cardRequest = await CardRequest.findOne({ userId: user._id }).sort({ requestDate: -1 });
        const kycRequest = await KycRequest.findOne({ userId: user._id }).sort({ submittedAt: -1 });
        const loans = await Loan.find({ userId: user._id }).sort({ appliedDate: -1 });

        res.render("admin/user-detail", {
            title: "User Details | Admin",
            user,
            transactions,
            cardRequest,
            kycRequest,
            loans,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin user detail error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/admin/users/:id/balance", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { action, amount, reason } = req.body;
        const user = await User.findById(req.params.id);

        if (action === "add") {
            user.balance += Number(amount);

            const transaction = new Transaction({
                userId: user._id,
                type: "deposit",
                amount: Number(amount),
                description: reason || "Admin adjustment - Credit",
                status: "completed",
                processedBy: req.session.userId,
                processedDate: new Date()
            });
            await transaction.save();

        } else if (action === "deduct") {
            if (user.balance < Number(amount)) {
                return res.redirect(`/admin/users/${user._id}?error=Insufficient balance`);
            }
            user.balance -= Number(amount);

            const transaction = new Transaction({
                userId: user._id,
                type: "withdrawal",
                amount: Number(amount),
                description: reason || "Admin adjustment - Debit",
                status: "completed",
                processedBy: req.session.userId,
                processedDate: new Date()
            });
            await transaction.save();
        }

        await user.save();
        res.redirect(`/admin/users/${user._id}?success=Balance updated successfully`);
    } catch (error) {
        console.error("Admin balance update error:", error);
        res.redirect(`/admin/users/${req.params.id}?error=Failed to update balance`);
    }
});

app.post("/admin/users/:id/toggle-admin", requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        user.isAdmin = !user.isAdmin;
        await user.save();

        res.redirect(`/admin/users/${user._id}?success=Admin status toggled`);
    } catch (error) {
        console.error("Admin toggle error:", error);
        res.redirect(`/admin/users/${req.params.id}?error=Failed to toggle admin status`);
    }
});

// ========== ADMIN TRANSFER APPROVAL (FIXED) ==========
app.get("/admin/transfers", requireAuth, requireAdmin, async (req, res) => {
    try {
        const pendingTransfers = await Transaction.find({
            type: "transfer",
            status: "pending"
        }).populate("fromUserId toUserId").sort({ date: -1 });

        const completedTransfers = await Transaction.find({
            type: "transfer",
            status: { $in: ["completed", "rejected"] }
        }).populate("fromUserId toUserId").sort({ date: -1 }).limit(50);

        res.render("admin/transfers", {
            title: "Transfer Approvals | Admin",
            pendingTransfers,
            completedTransfers,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin transfers error:", error);
        res.status(500).send("Server error");
    }
});

// FIXED: Approve transfer with better error handling
app.post("/admin/transfers/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) {
            return res.redirect("/admin/transfers?error=Transaction not found");
        }

        const recipient = await User.findById(transaction.toUserId);
        if (!recipient) {
            return res.redirect("/admin/transfers?error=Recipient not found");
        }

        // Credit recipient
        recipient.balance += transaction.amount;
        await recipient.save();

        // Update transaction status
        transaction.status = "completed";
        transaction.processedBy = req.session.userId;
        transaction.processedDate = new Date();
        await transaction.save();

        // Create transaction record for recipient
        const recipientTransaction = new Transaction({
            userId: recipient._id,
            type: "transfer",
            amount: transaction.amount,
            description: `Transfer from ${transaction.fromUserId?.accountNumber || 'unknown'}`,
            fromAccount: transaction.fromAccount,
            fromUserId: transaction.fromUserId,
            status: "completed",
            date: new Date()
        });
        await recipientTransaction.save();

        res.redirect("/admin/transfers?success=Transfer approved and recipient credited");
    } catch (error) {
        console.error("Transfer approval error:", error);
        res.redirect("/admin/transfers?error=Failed to approve transfer: " + error.message);
    }
});

// FIXED: Reject transfer with better error handling
app.post("/admin/transfers/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) {
            return res.redirect("/admin/transfers?error=Transaction not found");
        }

        const sender = await User.findById(transaction.fromUserId);
        if (!sender) {
            return res.redirect("/admin/transfers?error=Sender not found");
        }

        // Refund sender
        sender.balance += transaction.amount;
        await sender.save();

        // Update transaction status
        transaction.status = "rejected";
        transaction.processedBy = req.session.userId;
        transaction.processedDate = new Date();
        await transaction.save();

        // Create refund transaction record
        const refundTransaction = new Transaction({
            userId: sender._id,
            type: "deposit",
            amount: transaction.amount,
            description: "Refund for rejected transfer",
            status: "completed",
            processedBy: req.session.userId,
            processedDate: new Date()
        });
        await refundTransaction.save();

        res.redirect("/admin/transfers?success=Transfer rejected and sender refunded");
    } catch (error) {
        console.error("Transfer rejection error:", error);
        res.redirect("/admin/transfers?error=Failed to reject transfer: " + error.message);
    }
});

// ========== ADMIN CARD MANAGEMENT ==========
app.get("/admin/cards", requireAuth, requireAdmin, async (req, res) => {
    try {
        const pendingRequests = await CardRequest.find({ status: "pending" })
            .populate("userId")
            .sort({ requestDate: -1 });

        const processedRequests = await CardRequest.find({
            status: { $in: ["approved", "rejected"] }
        }).populate("userId")
          .sort({ processedDate: -1 })
          .limit(50);

        res.render("admin/cards", {
            title: "Card Requests | Admin",
            pendingRequests,
            processedRequests,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin cards error:", error);
        res.status(500).send("Server error");
    }
});

app.post("/admin/cards/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const cardRequest = await CardRequest.findById(req.params.id);

        const cardNumber = Math.floor(1000000000000000 + Math.random() * 9000000000000000).toString();
        const expiry = new Date();
        expiry.setFullYear(expiry.getFullYear() + 4);
        const cardExpiry = `${(expiry.getMonth() + 1).toString().padStart(2, '0')}/${expiry.getFullYear().toString().slice(-2)}`;
        const cardCVV = Math.floor(100 + Math.random() * 900).toString();

        await User.findByIdAndUpdate(cardRequest.userId, {
            hasCard: true,
            cardNumber: cardNumber,
            cardExpiry: cardExpiry,
            cardCVV: cardCVV,
            cardRequested: false
        });

        cardRequest.status = "approved";
        cardRequest.processedDate = new Date();
        cardRequest.processedBy = req.session.userId;
        await cardRequest.save();

        res.redirect("/admin/cards?success=Card approved successfully");
    } catch (error) {
        console.error("Card approval error:", error);
        res.redirect("/admin/cards?error=Failed to approve card");
    }
});

app.post("/admin/cards/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    try {
        const cardRequest = await CardRequest.findById(req.params.id);

        cardRequest.status = "rejected";
        cardRequest.processedDate = new Date();
        cardRequest.processedBy = req.session.userId;
        await cardRequest.save();

        await User.findByIdAndUpdate(cardRequest.userId, {
            cardRequested: false
        });

        res.redirect("/admin/cards?success=Card request rejected");
    } catch (error) {
        console.error("Card rejection error:", error);
        res.redirect("/admin/cards?error=Failed to reject card");
    }
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login");
});

// ========== ERROR HANDLING ==========
app.use((req, res) => {
    res.status(404).render("404", { title: "Page Not Found | Saxon Bank" });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render("500", { title: "Server Error | Saxon Bank" });
});

// ========== SERVER START ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Saxon Bank Professional Edition running on http://localhost:${PORT}`);
});
