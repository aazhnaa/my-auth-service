import dotenv from "dotenv";
dotenv.config()

import app from "./app.js";
import "./src/lib/redis.js";
import {connectDB} from "./src/lib/connectionDB.js";
import { validateEnv } from "./src/config/validateEnv.js";
validateEnv();
import {config} from "./src/config/index.js";

async function startServer(){
    try{
        await connectDB();
        app.listen(config.port, ()=>{
            console.log(`server is running on port ${config.port}`)
        })
    }
    catch(err){
        console.error("Startup failed: ", err);
        process.exit(1);
    }
}

startServer();
