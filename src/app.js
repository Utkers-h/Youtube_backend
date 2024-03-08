import express from "express"
import cookieParser from "cookie-parser"
import cors from "cors"

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

// Data in json format
app.use(express.json({
    limit: '16kb' // Maximum request body size.
}))

// While receiving data from  url encoded forms
app.use(express.urlencoded({ extended: true, limit: "16kb" }))
app.use(express.static("public"))
app.use(cookieParser())

// routes import 
import userRouter from './routes/user.routes.js'

// routes declaration 
app.use("/api/v1/users", userRouter) // we can't use app.get() since here we have to include  the  middleware function , since controller and routes have been separated
// pass control to user.routes file
// route will look like : http://localhost:8000/api/v1/users/register


export { app }