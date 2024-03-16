// it will verify whether the user exists  or not

import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model";


export const verifyJWT = asyncHandler(async (req,res,next)=>{
    // to obtain the access token , we can use cookie method or the req.headers method
    // since access tokens are commonly passed in the Authorization header using the Bearer token scheme. 
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
    
        if(!token){
            throw new ApiError(401,"Unauthorized request")
        }
    
        const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id).select(["-password -refreshToken"])
    
        if (!user) {
            throw new ApiError(401,'User does not exist')
        }
    
        req.user=user;
        next()
    } catch (error) {
        throw new ApiError(401, error?.message||"Invalid access Token")
    }


})