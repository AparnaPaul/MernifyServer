import { Admin } from "../models/adminModel.js";
import tryCatch from "../utils/tryCatch.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

export const loginAdmin = tryCatch(async (req, res) => {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    const errorMsg = "Auth failed: Email or password is incorrect";

    if (!admin) {
        return res.status(403).json({ message: errorMsg, success: false });
    }

    const isPasswordEqual = await bcrypt.compare(password, admin.password);
    if (!isPasswordEqual) {
        return res.status(403).json({ message: errorMsg, success: false });
    }

    // Ensure the admin role is stored in the database
    const role = "admin";  // Assuming all users logging in here are admins

    const jwtToken = jwt.sign(
        { email: admin.email, _id: admin._id, role },  // Include role in the token
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
    );

    res.cookie('token', jwtToken, { 
        httpOnly: false,
        secure: process.env.NODE_ENV === "production" ? true : false, 
        sameSite: "Lax",
        maxAge: 24 * 60 * 60 * 1000 
    });

    const adminResponse = { ...admin._doc, role: "admin" }; // Add role to response
    delete adminResponse.password;

    res.status(200).json({ message: "Login success", success: true, admin: adminResponse, token: jwtToken });
});

export const signupAdmin = tryCatch(async (req, res) => {
    const { username, email, password, mobile } = req.body;

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
        return res.status(409).json({ message: "Admin already exists, you can login", success: false });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new Admin({ username, email, password: hashedPassword, mobile });

    await admin.save();

    const jwtToken = jwt.sign(
        { email: admin.email, _id: admin._id },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
    );

    res.cookie('token', jwtToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    const adminResponse = { ...admin._doc };
    delete adminResponse.password;

    res.status(201).json({ message: "Signup success", success: true, admin: adminResponse });
});

export const myProfile = tryCatch(async (req, res) => {
    const admin = await Admin.findById(req.admin._id);
    const adminResponse = { ...admin._doc };
    delete adminResponse.password;
    res.json(adminResponse);
});

export const logoutAdmin = tryCatch(async (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: "Admin logged out successfully", success: true });
});

export const updateAdminProfile = tryCatch(async (req, res) => {
    const { username, mobile } = req.body;
    const admin = await Admin.findByIdAndUpdate(req.admin._id, { username, mobile }, { new: true });

    // Remove password from the response
    const adminResponse = { ...admin._doc };
    delete adminResponse.password;

    res.status(200).json({
        message: "Admin profile updated successfully",
        success: true,
        admin: adminResponse
    });
});


export const deactivateAdminAccount = tryCatch(async (req, res) => {
    await Admin.findByIdAndDelete(req.admin._id);
    res.clearCookie('token');
    res.status(200).json({
        message: "Admin account deactivated successfully",
        success: true
    });
});