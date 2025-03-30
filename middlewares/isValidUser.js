import jwt from "jsonwebtoken";
import { User } from "../models/userModel.js";

export const isValidUser = async (req, res, next) => {
  try {
    // Collect token from cookies
    const token = req.cookies.token;

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        message: "User not authorized. Please log in.",
        success: false,
      });
    }

    // Decode the token
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);

    // Find the user by ID from the decoded token
    const user = await User.findById(decodedData._id);

    // Check if user exists
    if (!user) {
      return res.status(404).json({
        message: "User not found. Please sign up.",
        success: false,
      });
    }

    // Attach the user object to the request
    req.user = user;

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    console.error("Error in isValidUser middleware:", error);

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
