const { store } = require('./lib/store');

exports.handler = async () => {
  try {
    const s = store();
    const now = Date.now();
    const { blobs } = await s.list({ prefix: 'user:' });
    let unbanned = 0;
    for (const b of blobs) {
      const u = await s.get(b.key, { type:'json' }).catch(()=>null);
      if (!u || !u.banned) continue;
      const expiresAt = Number(u.banExpiresAt || 0);
      if (!expiresAt || expiresAt > now) continue;
      u.banned=false; u.bannedAt=null; u.banReason=null; u.banExpiresAt=0;
      await s.setJSON(`user:${u.username}`,u);
      const { blobs: revoked } = await s.list({prefix:'revoked-ban:'}).catch(()=>({blobs:[]}));
      for (const rb of revoked) {
        const mark=await s.get(rb.key,{type:'json'}).catch(()=>null);
        if(mark?.username===u.username) await s.delete(rb.key).catch(()=>{});
      }
      unbanned++;
    }
    return {statusCode:200,body:JSON.stringify({ok:true,unbanned})};
  } catch(err) {
    return {statusCode:500,body:JSON.stringify({error:String(err)})};
  }
};
