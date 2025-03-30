import { Product } from "../models/productModel.js";
import { Review } from "../models/reviewModel.js";
import tryCatch from "../utils/tryCatch.js";


export const createReview = tryCatch(async (req, res) => {
    const { productId, rating, reviewComment } = req.body;

    if (!rating || !reviewComment) {
        return res.status(400).json({
            message: "Rating and comment are required"
        });
    }

    const product = await Product.findById(productId);
    if (!product) {
        return res.status(404).json({
            message: "Product not found"
        });
    }

    const review = await Review.create({
        userId: req.user.id,
        productId,
        rating,
        reviewComment
    });

    res.status(201).json({
        message: "Review added successfully", review
    });
})


export const getReviewsByProduct = tryCatch(async (req, res) => {
    const reviews = await Review.find({ productId: req.params.productId })
        .populate("userId", "name");

    if (!reviews) {
        return res.status(404).json({
            message: "No reviews found for this product"
        });
    }

    res.json({ reviews });

})

export const deleteReview = tryCatch(async (req, res) => {

    const review = await Review.findById(req.params.reviewId);
    if (!review) return res.status(404).json({
        message: "Review not found"
    });

    //Check if the user is authorized to delete the review
    if (review.userId.toString() !== req.user.id) {
        return res.status(403).json({
            message: "Not authorized to delete this review"
        });
    }

    await review.deleteOne();
    res.json({
        message: "Review deleted successfully"
    });

})


