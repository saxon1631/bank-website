require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const nodemailer = require("nodemailer");

const app = express();

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
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false // optional, helps with some firewalls
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
    
    // Profile Settings
    phone: { type: String, default: null },
    address: { type: String, default: null },
    dateOfBirth: { type: Date, default: null },
    
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

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const CardRequest = mongoose.model("CardRequest", cardRequestSchema);
const KycRequest = mongoose.model("KycRequest", kycRequestSchema);

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

// ========== ROUTES ==========
app.get("/", (req, res) => {
    res.redirect(req.session.userId ? "/dashboard" : "/login");
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

// Register POST
app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("register", {
                title: "Register | Saxon Bank",
                error: "Email already registered",
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountNumber = Math.floor(1000000000 + Math.random() * 9000000000).toString();
        const user = new User({
            name,
            email,
            password: hashedPassword,
            accountNumber,
            hasCard: false,
            cardRequested: false
        });
        await user.save();
        res.redirect("/login?success=Registration successful! Please login.");
    } catch (error) {
        console.error(error);
        res.render("register", {
            title: "Register | Saxon Bank",
            error: "Registration failed. Please try again.",
        });
    }
});

// ========== PASSWORD RESET ROUTES ==========

// Forgot Password Page
app.get("/forgot-password", (req, res) => {
    res.render("forgot-password", {
        title: "Forgot Password | Saxon Bank",
        error: req.query.error || null,
        success: req.query.success || null
    });
});

// Forgot Password POST (sends real email via Zoho)
app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            // Don't reveal if email exists
            return res.redirect("/forgot-password?success=If that email exists, we'll send reset instructions");
        }
        
        // Generate a random token
        const resetToken = Math.random().toString(36).slice(-8); // 8-character token
        const expiry = Date.now() + 3600000; // 1 hour
        
        user.resetToken = resetToken;
        user.resetTokenExpiry = expiry;
        await user.save();
        
        // Create reset link (use your domain – for now localhost, later your live URL)
        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
        
        // Send email via Zoho
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

// Reset Password Page (GET)
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
        valid: true // for your custom template
    });
});

// Reset Password POST
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
        // Hash new password
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
            valid: false // hide form, show success
        });
    } catch (error) {
        console.error(error);
        res.redirect("/forgot-password?error=Something went wrong");
    }
});

// ========== PROFILE & SETTINGS ROUTES ==========

// Profile Page
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

// Update Profile
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

// Settings Page
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

// Update Settings
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

// Privacy Page
app.get("/privacy", requireAuth, async (req, res) => {
    res.render("privacy", {
        title: "Privacy & Security | Saxon Bank",
        success: req.query.success || null,
        error: req.query.error || null
    });
});

// Notifications Page
app.get("/notifications", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render("notifications", {
            title: "Notifications | Saxon Bank",
            user,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Notifications error:", error);
        res.redirect("/dashboard");
    }
});

// Limits Page
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
        const transactions = await Transaction.find({ userId: user._id })
            .sort({ date: -1 });
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

// ========== KYC VERIFICATION ROUTES ==========

// KYC Page
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

// Submit KYC Documents
app.post("/kyc/submit", requireAuth, async (req, res) => {
    try {
        const { documentType } = req.body;
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
        
        const kycRequest = new KycRequest({
            userId: user._id,
            documents: [{
                type: documentType,
                url: "/uploads/placeholder.jpg",
                filename: "document.jpg"
            }],
            status: "pending"
        });
        await kycRequest.save();
        
        user.kycPending = true;
        user.kycProgress = 33;
        await user.save();
        
        res.redirect("/kyc?success=Documents submitted successfully! We'll review them within 24 hours.");
    } catch (error) {
        console.error("KYC submission error:", error);
        res.redirect("/kyc?error=Failed to submit documents");
    }
});

// ========== ADMIN KYC MANAGEMENT ==========

// Admin: View pending KYC requests
app.get("/admin/kyc", requireAuth, requireAdmin, async (req, res) => {
    try {
        const pendingRequests = await KycRequest.find({ status: "pending" })
            .populate("userId")
            .sort({ submittedAt: -1 });
            
        const processedRequests = await KycRequest.find({ 
            status: { $in: ["approved", "rejected"] } 
        }).populate("userId")
          .sort({ processedAt: -1 })
          .limit(50);
        
        res.render("admin/kyc", {
            title: "KYC Requests | Admin",
            pendingRequests,
            processedRequests,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin KYC error:", error);
        res.status(500).send("Server error");
    }
});

// Admin: Approve KYC
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
        
        res.redirect("/admin/kyc?success=KYC approved successfully");
    } catch (error) {
        console.error("KYC approval error:", error);
        res.redirect("/admin/kyc?error=Failed to approve KYC");
    }
});

// Admin: Reject KYC
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
        
        res.redirect("/admin/kyc?success=KYC rejected");
    } catch (error) {
        console.error("KYC rejection error:", error);
        res.redirect("/admin/kyc?error=Failed to reject KYC");
    }
});

// Dashboard
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

// Deposit POST
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

// Transfer POST - PENDING STATUS
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
        const transactions = await Transaction.find({ userId: user._id })
            .sort({ date: -1 });
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

// Apply for Card POST
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
// Admin Dashboard
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
        
        res.render("admin/dashboard", {
            title: "Admin Dashboard | Saxon Bank",
            users: users,
            pendingTransfers: pendingTransfers,
            pendingCards: pendingCards,
            pendingKyc: pendingKyc,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin dashboard error:", error);
        res.status(500).send("Server error");
    }
});

// ========== ADMIN USER MANAGEMENT ==========

// View all users
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

// View single user
app.get("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const transactions = await Transaction.find({ userId: user._id }).sort({ date: -1 });
        const cardRequest = await CardRequest.findOne({ userId: user._id }).sort({ requestDate: -1 });
        const kycRequest = await KycRequest.findOne({ userId: user._id }).sort({ submittedAt: -1 });
        
        res.render("admin/user-detail", {
            title: "User Details | Admin",
            user,
            transactions,
            cardRequest,
            kycRequest,
            formatCurrency,
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Admin user detail error:", error);
        res.status(500).send("Server error");
    }
});

// Update user balance (ADD or DEDUCT)
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

// Toggle admin status
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

// ========== ADMIN TRANSFER APPROVAL ==========

// View pending transfers
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

// Approve transfer
app.post("/admin/transfers/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        const recipient = await User.findById(transaction.toUserId);
        
        recipient.balance += transaction.amount;
        await recipient.save();
        
        transaction.status = "completed";
        transaction.processedBy = req.session.userId;
        transaction.processedDate = new Date();
        await transaction.save();
        
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
        res.redirect("/admin/transfers?error=Failed to approve transfer");
    }
});

// Reject transfer (refund sender)
app.post("/admin/transfers/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        const sender = await User.findById(transaction.fromUserId);
        
        sender.balance += transaction.amount;
        await sender.save();
        
        transaction.status = "rejected";
        transaction.processedBy = req.session.userId;
        transaction.processedDate = new Date();
        await transaction.save();
        
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
        res.redirect("/admin/transfers?error=Failed to reject transfer");
    }
});

// ========== ADMIN CARD MANAGEMENT ==========

// View card requests
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

// Approve card request (with 4-year expiry)
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

// Reject card request
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
