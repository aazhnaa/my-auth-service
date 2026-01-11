export function validateEnv(){
    const required = [
        "MONGODB_URI",
        "UPSTASH_URL",
        "JWT_SECRET",
        "PORT"
    ]
    const missing = required.filter((key)=>!process.env[key]);

    if(missing.length){
        console.error("Missing env variables:", missing.join(", "));
        process.exit(1);
    }
}