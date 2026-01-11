import {redis} from '../lib/redis.js';
export const checkLoginLock = async(identifier) =>{
    const lockKey = `login:lock:${identifier}`;
    const ttl = await redis.ttl(lockKey);
    console.log("CHECK LOCK:", identifier, "TTL:", ttl);
    //if (ttl === -1) return 9999;
    if(ttl > 0){
        return ttl;
    }

    return null;
}


// export const recordLoginFailure = async(identifier) =>{
//     const failkey = `login:fail:${identifier}`;
//     const lockKey = `login:lock:${identifier}`;
//     const attempts = await redis.incr(failkey);
//     console.log("LOGIN FAIL:", identifier, "ATTEMPTS:", attempts);

//     // keep failure count for 24 hours
//     if(attempts === 1){
//         await redis.expire(failkey, 24*60*60)
//     }

//     if (attempts >= 16) {
//         await redis.set(lockKey, "locked", { EX: 1800 }); // 30 min
//     } else if (attempts >= 11) {
//         await redis.set(lockKey, "locked", { EX: 300 });  // 5 min
//     } else if (attempts >= 6) {
//         await redis.set(lockKey, "locked", { EX: 60 });   // 1 min
//     }

//     return attempts;
// }

export const recordLoginFailure = async (identifier) => {
  const failKey = `login:fail:${identifier}`;
  const lockKey = `login:lock:${identifier}`;

  const attempts = await redis.incr(failKey);

  if (attempts === 1) {
    await redis.expire(failKey, 24 * 60 * 60);
  }

  let lockTime = null;

  if (attempts >= 16) lockTime = 1800;
  else if (attempts >= 11) lockTime = 300;
  else if (attempts >= 6) lockTime = 60;

  if (lockTime) {
    // IMPORTANT: overwrite key + expiry EVERY time
    await redis.set(lockKey, "locked", { ex: lockTime });
  }

  return attempts;
};



export const resetLoginFailures = async(identifier) =>{
    await redis.del(`login:fail:${identifier}`);
    await redis.del(`login:lock:${identifier}`);
}