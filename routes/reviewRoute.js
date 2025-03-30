import express from "express";
import { isValidUser } from "../middlewares/isValidUser.js";
import { createReview, getReviewsByProduct, deleteReview} from "../controllers/reviewController.js"

const router = express.Router();

router.post('/review/add', isValidUser, createReview)
router.get('/review/:productId', isValidUser, getReviewsByProduct)
router.delete('/review/:reviewId', isValidUser, deleteReview)


export default router;