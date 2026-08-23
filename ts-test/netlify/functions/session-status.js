const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, getClientIp } = require('./lib/security');

function json(statusCode, body) {
  return { statusCode, headers: {'Content-Type':'application/json','Cache-Control':'no-store'}, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') return { statusCode:405, body:'Method Not Allowed' };
  try {
    const s=store();
    const ipBan=await enforceIpBan(s,event);
    if(ipBan) return json(403,{
      error:'Цей IP-адрес заблоковано', ipBlocked:true,
      ipBanReason:ipBan.reason||'', ipBanExpiresAt:Number(ipBan.expiresAt||0),
      ipBanPermanent:!Number(ipBan.expiresAt||0)
    });

    const token=extractToken(event);
    if(!token) return json(401,{error:'Сесія недійсна',sessionExpired:true});

    const sess=await validateSession(s,token,event);
    if(sess?.banned){
      const exp=Number(sess.banExpiresAt||0);
      if(exp && exp<=Date.now()){
        // The account ban has expired. The old token is still invalid;
        // the user must log in again to obtain a fresh session.
        await s.delete(`session:${token}`).catch(()=>{});
        return json(401,{error:'Термін блокування завершено. Увійди знову.',sessionExpired:true,banEnded:true});
      }
      return json(403,{error:'Акаунт заблоковано',banned:true,
        banReason:sess.banReason||'',banExpiresAt:exp,banPermanent:!exp});
    }

    if(!sess){
      // If the token was revoked by a ban, show ban information only while
      // the account is still actually banned. An unban removes the marker.
      const revoked=await s.get(`revoked-ban:${token}`,{type:'json'}).catch(()=>null);
      if(revoked){
        const user=revoked.username ? await s.get(`user:${revoked.username}`,{type:'json'}).catch(()=>null) : null;
        if(user?.banned){
          const exp=Number(user.banExpiresAt||revoked.expiresAt||0);
          if(exp && exp<=Date.now()){
            user.banned=false; user.banReason=null; user.banExpiresAt=0;
            await s.setJSON(`user:${user.username}`,user).catch(()=>{});
          } else {
            return json(403,{error:'Акаунт заблоковано',banned:true,
              banReason:user.banReason||revoked.reason||'',banExpiresAt:exp,banPermanent:!exp});
          }
        }
        // Unbanned or expired: stale ban marker is removed and old token
        // stays invalid.
        await s.delete(`revoked-ban:${token}`).catch(()=>{});
      }
      return json(401,{error:'Сесія завершена. Увійди знову.',sessionExpired:true});
    }

    return json(200,{ok:true,username:sess.username,expiresAt:sess.expiresAt,lastActive:sess.lastActive,ip:getClientIp(event)});
  } catch(err) {
    return json(500,{error:String(err)});
  }
};
