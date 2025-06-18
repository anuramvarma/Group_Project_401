// Initialize Firebase Authentication
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js';
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut } from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js';
import { getFirestore, doc, setDoc, getDoc, collection } from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js';

// Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyCgR3k3itG2MCHrGU4quF3jwSoM-U5Tw48", // Replace with your actual API key
    authDomain: "farmgrower-7ba4f.firebaseapp.com",
    projectId: "farmgrower-7ba4f",
    storageBucket: "farmgrower-7ba4f.appspot.com",
    messagingSenderId: "106352953126118201066",
    appId: "1:443080881556:web:4603af24a79459f8190b81" // Replace with your actual App ID
};

// Initialize Firebase
let app;
let auth;
let db;

try {
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    db = getFirestore(app);
    console.log("Firebase initialized successfully");
} catch (error) {
    console.error("Firebase initialization error:", error);
    throw new Error("Failed to initialize Firebase. Please check your configuration.");
}

// Function to hash password
async function hashPassword(password) {
    try {
        // Using the Web Crypto API for password hashing
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    } catch (error) {
        console.error("Password hashing error:", error);
        throw new Error("Failed to hash password");
    }
}

// Initialize admin account
async function initializeAdminAccount() {
    try {
        const adminEmail = 'admin@farmgrower.com';
        const adminPassword = 'admin123';
        
        // Check if admin account exists
        const adminDoc = await getDoc(doc(db, "users", "admin"));
        
        if (!adminDoc.exists()) {
            console.log("Creating admin account...");
            // Create admin user in Firebase Auth
            const userCredential = await createUserWithEmailAndPassword(auth, adminEmail, adminPassword);
            const adminUser = userCredential.user;
            
            // Hash admin password
            const hashedPassword = await hashPassword(adminPassword);
            
            // Store admin data in Firestore
            await setDoc(doc(db, "users", "admin"), {
                email: adminEmail,
                passwordHash: hashedPassword,
                role: 'admin',
                name: 'System Administrator',
                createdAt: new Date().toISOString()
            });
            
            console.log("Admin account created successfully");
        }
    } catch (error) {
        console.error("Admin initialization error:", error);
    }
}

// Call initializeAdminAccount when the app starts
initializeAdminAccount();

// Register new user
export async function registerUser(email, password, userData) {
    try {
        if (!auth || !db) {
            throw new Error("Firebase not properly initialized");
        }

        console.log("Starting registration process...");
        console.log("User data:", { email, ...userData });

        // Create user with email and password
        console.log("Creating user with email and password...");
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        console.log("User created successfully:", user.uid);

        // Hash the password before storing
        console.log("Hashing password...");
        const hashedPassword = await hashPassword(password);

        // Store additional user data in Firestore
        console.log("Storing user data in Firestore...");
        const userRef = doc(db, "users", user.uid);
        const userDataToStore = {
            ...userData,
            email: email,
            passwordHash: hashedPassword, // Store hashed password instead of plain text
            createdAt: new Date().toISOString(),
            role: 'farmer'
        };
        console.log("User data to store:", { ...userDataToStore, passwordHash: '[REDACTED]' });
        
        await setDoc(userRef, userDataToStore);
        console.log("User data stored in Firestore successfully");

        // Also store in SignUp-Details collection for backward compatibility
        console.log("Storing data in SignUp-Details collection...");
        const signUpRef = doc(collection(db, "SignUp-Details"));
        const signUpData = {
            Name: userData.name,
            Email: email,
            PasswordHash: hashedPassword, // Store hashed password instead of plain text
            Phone: userData.phone,
            Address: userData.address,
            LandArea: userData.landArea,
            createdAt: new Date().toISOString()
        };
        console.log("SignUp data to store:", { ...signUpData, PasswordHash: '[REDACTED]' });
        
        await setDoc(signUpRef, signUpData);
        console.log("SignUp data stored successfully");

        return { success: true, user };
    } catch (error) {
        console.error("Registration error:", error);
        let errorMessage = "Registration failed. ";
        
        switch (error.code) {
            case 'auth/api-key-not-valid':
                errorMessage = "Firebase configuration error. Please contact support.";
                break;
            case 'auth/email-already-in-use':
                errorMessage += "This email is already registered.";
                break;
            case 'auth/invalid-email':
                errorMessage += "Invalid email address.";
                break;
            case 'auth/operation-not-allowed':
                errorMessage += "Email/password accounts are not enabled.";
                break;
            case 'auth/weak-password':
                errorMessage += "Password is too weak.";
                break;
            case 'permission-denied':
                errorMessage += "Database permission denied. Please check Firebase rules.";
                break;
            default:
                errorMessage += error.message;
        }
        
        return { success: false, error: errorMessage };
    }
}

// Login user
export async function loginUser(email, password) {
    try {
        if (!auth || !db) {
            throw new Error("Firebase not properly initialized");
        }

        console.log("Attempting login for:", email);
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        console.log("User logged in successfully:", user.uid);

        // Get user data from Firestore
        console.log("Fetching user data from Firestore...");
        const userDoc = await getDoc(doc(db, "users", user.uid));
        if (!userDoc.exists()) {
            console.error("User document not found in Firestore");
            throw new Error("User data not found");
        }
        
        const userData = userDoc.data();
        if (userData.role === 'admin') {
            throw new Error("Please use the admin login form");
        }
        
        console.log("User data retrieved successfully");
        return { success: true, user, userData };
    } catch (error) {
        console.error("Login error:", error);
        let errorMessage = "Login failed. ";
        
        switch (error.code) {
            case 'auth/invalid-email':
                errorMessage += "Invalid email address.";
                break;
            case 'auth/user-disabled':
                errorMessage += "This account has been disabled.";
                break;
            case 'auth/user-not-found':
                errorMessage += "No account found with this email.";
                break;
            case 'auth/wrong-password':
                errorMessage += "Incorrect password.";
                break;
            default:
                errorMessage += error.message;
        }
        
        return { success: false, error: errorMessage };
    }
}

// Login admin
export async function loginAdmin(email, password) {
    try {
        if (!auth || !db) {
            throw new Error("Firebase not properly initialized");
        }

        console.log("Attempting admin login for:", email);
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        console.log("Admin logged in successfully:", user.uid);

        // Get admin data from Firestore
        console.log("Fetching admin data from Firestore...");
        const adminDoc = await getDoc(doc(db, "users", "admin"));
        if (!adminDoc.exists()) {
            console.error("Admin document not found in Firestore");
            throw new Error("Admin account not found");
        }
        
        const adminData = adminDoc.data();
        if (adminData.email !== email || adminData.role !== 'admin') {
            throw new Error("Invalid admin credentials");
        }
        
        console.log("Admin data retrieved successfully");
        return { success: true, user, userData: adminData };
    } catch (error) {
        console.error("Admin login error:", error);
        let errorMessage = "Admin login failed. ";
        
        switch (error.code) {
            case 'auth/invalid-email':
                errorMessage += "Invalid email address.";
                break;
            case 'auth/user-disabled':
                errorMessage += "This account has been disabled.";
                break;
            case 'auth/user-not-found':
                errorMessage += "No admin account found with this email.";
                break;
            case 'auth/wrong-password':
                errorMessage += "Incorrect password.";
                break;
            default:
                errorMessage += error.message;
        }
        
        return { success: false, error: errorMessage };
    }
}

// Logout user
export async function logoutUser() {
    try {
        if (!auth) {
            throw new Error("Firebase not properly initialized");
        }

        await signOut(auth);
        localStorage.removeItem('currentUser');
        console.log("User logged out successfully");
        return { success: true };
    } catch (error) {
        console.error("Logout error:", error);
        return { success: false, error: error.message };
    }
}

// Get current user
export function getCurrentUser() {
    return auth?.currentUser;
}

// Check if user is logged in
export function isUserLoggedIn() {
    return !!auth?.currentUser;
} 