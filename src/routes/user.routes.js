import { Router } from "express";
import { loginUser, logoutUser, registerUser } from "../controllers/user.controller.js";
import {upload}  from "../middlewares/multer.middleware.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";

const  router = Router();

router.route("/register").post(
    // injecting middlewares to get images 
    upload.fields([
        {
            name: 'avatar',
            maxCount: 1
        },
        {
            name:'coverImage',
            maxCount: 1
        }
    ]),
    registerUser
    )

router.route("/login").post(loginUser)

// secured routes
// to verify whether the user is loggedIn , we will inject the auth middleware
// that's why we have written next() to run the next middleware functions
router.route("/logout").post(verifyJWT,logoutUser)


export default router