import express from "express";
import { deactivateAccount, loginUser, logoutUser, myProfile, signupUser, updateProfile } from "../controllers/userController.js";
import { loginValidation, signupValidation } from "../middlewares/authValidation.js";
import { isValidUser } from "../middlewares/isValidUser.js";

const router = express.Router();

router.post('/user/login', loginValidation, loginUser)
router.post('/user/signup', signupValidation, signupUser)
router.get('/user/me', isValidUser, myProfile)
router.post('/user/logout', logoutUser)
router.put('/user/updateProfile', isValidUser, updateProfile)
router.post('/user/deactivate/:id', isValidUser, deactivateAccount)




export default router;
