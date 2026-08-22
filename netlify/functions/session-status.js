const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, getClientIp } = require('./lib/security');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };
  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return { statusCode: 403, headers: {'Content-Type':'application/json'}, body: JSON.stringify({error:'Цей IP-адрес заблоковано',ipBlocked:true,
      ipBanReason:ipBan.reason||'',ipBanExpiresAt:Number(ipBan.expiresAt||0),ipBanPermanent:!Number(ipBan.expiresAt||0)}) };
    const token = extractToken(event);
    const sess = await validateSession(s, token);
    if (!sess) {
      const revoked = token ? await s.get(`revoked-ban:${token}`, {type:'json'}).catch(()=>null) : null;
      if (revoked) {
        const exp=Number(revoked.expiresAt||0);
        if (exp && exp <= Date.now()) {
          await s.delete(`revoked-ban:${token}`).catch(()=>{});
          return {statusCode:401,headers:{'Content-Type':'application/json'},body:JSON.stringify({error:'Сесія завершена',sessionExpired:true})};
        }
        return {statusCode:403,headers:{'Content-Type':'application/json'},body:JSON.stringify({
          error:'Акаунт заблоковано',banned:true,banReason:revoked.reason||'',banExpiresAt:exp,banPermanent:!exp})};
      }
      return { statusCode:401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error:'Сесія недійсна', sessionExpired:true }) };
    }
    if (sess.banned) {
      const user=await s.get(`user:${sess.username}`,{type:'json'}).catch(()=>null);
      if(user?.banned){
        const expiresAt=Number(user.banExpiresAt||0);
        if(expiresAt && expiresAt<=Date.now()){
          user.banned=false;user.banReason=null;user.banExpiresAt=0;await s.setJSON(`user:${user.username}`,user);
        } else return {statusCode:403,headers:{'Content-Type':'application/json'},body:JSON.stringify({
          error:'Акаунт заблоковано',banned:true,banReason:user.banReason||'',banExpiresAt:expiresAt,banPermanent:!expiresAt})};
      }
    }
    return {
      statusCode: 200,
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        ok:true, username:sess.username, expiresAt:sess.expiresAt,
        lastActive:sess.lastActive, ip:getClientIp(event)
      })
    };
  } catch (err) {
    return { statusCode:500, body:JSON.stringify({error:String(err)}) };
  }
};
