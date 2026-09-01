const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest } = require('./lib/security');
function safeUrl(v){try{const u=new URL(String(v||''));return ['http:','https:'].includes(u.protocol)?u.toString().slice(0,1000):'';}catch{return '';}}
function cleanText(v,n=2000){return String(v??'').slice(0,n);}
function cleanNotes(notes){return (Array.isArray(notes)?notes:[]).slice(0,500).filter(n=>n&&typeof n==='object'&&!Array.isArray(n)).map(n=>({id:cleanText(n.id,120),text:cleanText(n.text,4000),deadline:/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(n.deadline||''))?String(n.deadline):'',done:n.done===true,createdAt:Number(n.createdAt)||Date.now(),link:safeUrl(n.link),attachments:(Array.isArray(n.attachments)?n.attachments:[]).slice(0,20).filter(a=>a&&typeof a==='object'&&!Array.isArray(a)).map(a=>({id:cleanText(a.id,80),name:cleanText(a.name,120),mime:cleanText(a.mime,120),size:Math.max(0,Number(a.size)||0)}))}));}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode:405, body:'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };
  try {
    const s=store();
    const ipBan=await enforceIpBan(s,event); if(ipBan)return{statusCode:403,body:JSON.stringify({error:'Цей IP-адрес заблоковано'})};
    const sess=await validateSession(s,extractToken(event),event); if(!sess)return{statusCode:401,body:JSON.stringify({error:'Сесія недійсна, увійди ще раз'})}; if(sess.banned)return{statusCode:403,body:JSON.stringify({error:'Акаунт заблоковано'})};
    if(String(event.body||'').length>900000)return{statusCode:413,body:JSON.stringify({error:'Дані розкладу завеликі'})};
    const body=JSON.parse(event.body||'{}'); const {schedule,subjects,cfg,notes,oneOffLessons}=body;
    if(!schedule||!Array.isArray(subjects))return{statusCode:400,body:JSON.stringify({error:'Немає даних розкладу'})};
    const baseUpdatedAt=Number(body.baseUpdatedAt||0);
    const current=await s.get(`schedule-data:${sess.userId}`,{type:'json',consistency:'strong'}).catch(()=>null);
    if(current && baseUpdatedAt && Number(current.updatedAt||0)>baseUpdatedAt) return{statusCode:409,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify({error:'Розклад було змінено на іншому пристрої. Онови дані та спробуй ще раз.',conflict:true,updatedAt:Number(current.updatedAt||0)})};

    const newNotes=cleanNotes(notes);
    const safeSubjects=subjects.slice(0,500).filter(x=>x&&typeof x==='object'&&!Array.isArray(x)).map(x=>({id:cleanText(x.id,120),name:cleanText(x.name,300),teacher:cleanText(x.teacher,300),room:cleanText(x.room,100),link:safeUrl(x.link)}));
    const safeOneOff=(Array.isArray(oneOffLessons)?oneOffLessons:[]).slice(0,500).filter(x=>x&&typeof x==='object'&&!Array.isArray(x)).map(x=>({...x,date:/^\d{4}-\d{2}-\d{2}$/.test(String(x.date||''))?String(x.date):'',time:/^\d{2}:\d{2}$/.test(String(x.time||''))?String(x.time):'',duration:Math.min(1440,Math.max(15,Number(x.duration)||45))}));
    const saved=await atomicUpdateJSON(`schedule-data:${sess.userId}`, current || {schedule:[],subjects:[],notes:[],oneOffLessons:[]}, existing=>{
      const nowCurrent=existing||{};
      if(baseUpdatedAt && Number(nowCurrent.updatedAt||0)>baseUpdatedAt){const err=new Error('SCHEDULE_CONFLICT');err.code='SCHEDULE_CONFLICT';throw err;}
      return {schedule,subjects:safeSubjects,notes:newNotes,oneOffLessons:safeOneOff,notif10:cfg?.notif10!==false,notif5:cfg?.notif5!==false,updatedAt:Date.now()};
    });

    // Whole-note deletions are reconciled by the admin orphan cleanup. We do not
    // mutate file metadata here because a concurrent upload may be in flight.

    return{statusCode:200,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify({ok:true,updatedAt:saved.value.updatedAt})};
  }catch(err){
    if(err.code==='SCHEDULE_CONFLICT')return{statusCode:409,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify({error:'Розклад було змінено на іншому пристрої. Онови дані та спробуй ще раз.',conflict:true})};
    const requestId=String(event.headers?.['x-nf-request-id']||event.headers?.['X-Nf-Request-Id']||'').slice(0,80); console.error('save-schedule failed',{requestId,code:err?.code||'UNKNOWN',name:err?.name||'Error'}); return{statusCode:500,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify({error:'Не вдалося зберегти розклад',requestId:requestId||undefined})};
  }
};
