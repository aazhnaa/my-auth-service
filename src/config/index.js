export const config = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: process.env.PORT || 5000,

  mongoUri: process.env.MONGODB_URI,
  redisUrl: process.env.UPSTASH_URL,

  jwtSecret: process.env.JWT_SECRET,
};
