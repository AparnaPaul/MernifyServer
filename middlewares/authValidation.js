import joi from "joi"

export const signupValidation = (req, res, next) => {
    const schema = joi.object({
        username: joi.string().min(3).max(10).required(),
        email: joi.string().email().required(),
        password: joi.string().min(4).max(10).required(),
        mobile: joi.string().regex(/^\d{10}$/).required()

    });

    const { error } = schema.validate(req.body)
    if (error) {
        return res.status(400).json({
            message: "Bad Request", error
        })
    }
    next();
}

export const loginValidation = (req, res, next) => {
    const schema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().min(4).max(10).required()

    });

    const { error } = schema.validate(req.body)
    if (error) {
        return res.status(400).json({
            message: "Bad Request", error
        })
    }
    next();
}