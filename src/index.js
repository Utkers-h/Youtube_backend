
import connectDB from "./db/index.js";
import dotenv from "dotenv"

dotenv.config({
    path:'./env'
})

connectDB()
.then(()=>{
    // Handling errors before listening  to the server
    app.on("Error", (error)=>{
        console.log("Error: ",error)
    })

    app.listen(process.env.PORT || 8000 ,()=>{
        console.log(`Server is running at port:  ${process.env.PORT}`);
    })
})
.catch((error)=>{
    console.log("Error connecting to database: ",error)
})









/* First approach
const app =express();
// IIFE
(async () => { 
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        app.on("Error", (error)=>{
            console.log("Error: ",error)
        })

        app.listen(process.env.PORT ,()=>{
            console.log(`Server is running on port ${process.env.PORT}`);
        })

    } catch (error) {
        console.error("Error: " ,error)
        throw error
    }
})()
*/