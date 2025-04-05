import { User } from "../models/userModel.js";
import tryCatch from "../utils/tryCatch.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

export const loginUser = tryCatch(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email })
    const errorMsg = "Auth failed email or password is wrong"
    if (!user) {
        return res.status(403).json({
            message: errorMsg,
            success: false
        })
    }
    const isPasswordEqual = await bcrypt.compare(password, user.password);
    if (!isPasswordEqual) {
        return res.status(403).json({
            message: errorMsg,
            success: false
        })
    }

    const jwtToken = jwt.sign({ email: user.email, _id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
    )
    // Store token in cookie
    res.cookie('token', jwtToken, { sameSite: "None",
        secure: false,
        httpOnly: false, path: "/",
    });

    // Remove password from the response
    const userResponse = { ...user._doc };
    delete userResponse.password;

    res.status(200).json({
        message: "Login success",
        success: true,
        user: userResponse
    })
})

export const signupUser = tryCatch(async (req, res) => {
    const { username, email, password, mobile } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(409).json({
            message: "User already exists, you can login",
            success: false
        });
    }


    const hashedPassword = await bcrypt.hash(password, 10);


    const user = new User({
        username,
        email,
        password: hashedPassword,
        mobile
    });

    await user.save();

    const jwtToken = jwt.sign(
        { email: user.email, _id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
    );

    // Store token in cookie
    res.cookie('token', jwtToken, { sameSite: "None",
        secure: false,
        httpOnly: false, path: "/",
    });

    // Remove password from the response
    const userResponse = { ...user._doc };
    delete userResponse.password;

    res.status(201).json({
        message: "Signup success",
        success: true,
        user: userResponse
    });
});


export const myProfile = tryCatch(async (req, res) => {
    const user = await User.findById(req.user._id);

    // Remove password from the response
    const userResponse = { ...user._doc };
    delete userResponse.password;

    res.json(userResponse);
});

export const logoutUser = tryCatch(async (req, res) => {
    res.clearCookie('token');
    res.status(200).json({
        message: "Logged out successfully",
        success: true
    });
});

export const updateProfile = tryCatch(async (req, res) => {
    const { username, mobile } = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, { username, mobile }, { new: true });

    // Remove password from the response
    const userResponse = { ...user._doc };
    delete userResponse.password;

    res.status(200).json({
        message: "Profile updated successfully",
        success: true,
        user: userResponse
    });
});


export const deactivateAccount = tryCatch(async (req, res) => {
    await User.findByIdAndDelete(req.user._id);
    res.clearCookie('token');
    res.status(200).json({
        message: "Account deactivated successfully",
        success: true
    });
});