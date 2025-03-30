import jwt from "jsonwebtoken";
import { Admin } from "../models/adminModel.js";

export const isValidAdmin = async (req, res, next) => {
  try {
    // Collect token from cookies
    const token = req.cookies.token;

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        message: "Admin not authorized. Please log in.",
        success: false,
      });
    }

    // Decode the token
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);

    // Find the admin by ID from the decoded token
    const admin = await Admin.findById(decodedData._id);

    // Check if admin exists
    if (!admin) {
      return res.status(404).json({
        message: "Admin not found. Access denied.",
        success: false,
      });
    }

    // Attach the admin object to the request
    req.admin = { ...admin._doc, role: "admin" }; // Ensure role is attached


    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    console.error("Error in isValidAdmin middleware:", error);

    // Handle specific JWT errors
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        message: "Invalid token. Please log in again.",
        success: false,
      });
    }

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Token expired. Please log in again.",
        success: false,
      });
    }

    // Handle other errors
    res.status(500).json({
      message: "Internal server error. Please try again later.",
      success: false,
    });
  }
};
