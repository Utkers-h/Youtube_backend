import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from '../models/user.model.js'
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation (empty field , invalid data fields)
    // check if user already  exists in the database: username , email
    // check for images , check for avatar
    // upload them to cloudinary , avatar
    // create user objects - create entry in db
    // remove password and refresh token field from response
    // check for user creation 
    // return response

    const { fullname, email, username, password } = req.body
    // console.log("email:", email)

    // checking for validation of empty fields
    if (
        [fullname, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, 'All fields are required!!')
    }

    const existeduser =  await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existeduser) {
        throw new ApiError(409, "Email or Username is taken!")
    }

    const avatarLocalPath = req.files?.avatar?.[0]?.path
    const coverImagepath = req.files?.coverimage?.[0]?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar field is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImagepath)

    if (!avatar) {
        throw new ApiError(400, "Avatar field is required")
    }


    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()

    })

    // checking whether the user obj is created with help of _id (that is created by mongoose for every data entry)
    // if the user is found then remove the password & refreshToken field 
    const  createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user.")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered Successfully")
    )

})


export { registerUser }