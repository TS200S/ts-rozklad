const { store } = require('./lib/store');

exports.handler = async () => {
  try {
    const s = store();
    const now = Date.now();
    const { blobs } = await s.list({ prefix: 'user:' });
    let unbanned = 0, orphanedFiles = 0;
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

    // Reconcile file metadata left by interrupted note/file transactions.
    // Run this heavier scan every 15 minutes, not on every scheduler tick.
    if (new Date().getUTCMinutes() % 15 === 0) {
    const { blobs: fileMetaBlobs } = await s.list({ prefix: 'file-meta:' });
    for (const b of fileMetaBlobs) {
      const userId = b.key.slice('file-meta:'.length);
      if (!userId) continue;
      try {
        const data = await s.get(`schedule-data:${userId}`, { type: 'json', consistency: 'strong' });
        const referenced = new Set();
        for (const note of (Array.isArray(data?.notes) ? data.notes : [])) {
          for (const a of (Array.isArray(note?.attachments) ? note.attachments : [])) {
            if (a?.id) referenced.add(String(a.id));
          }
        }
        const current = await s.get(b.key, { type: 'json', consistency: 'strong' });
        const list = Array.isArray(current) ? current : [];
        const orphanGraceMs = 60 * 60 * 1000;
        const cutoff = Date.now() - orphanGraceMs;
        const orphaned = list.filter(meta => meta?.id && !referenced.has(String(meta.id)) && Number(meta.createdAt || 0) < cutoff);
        if (!orphaned.length) continue;
        const { atomicUpdateJSON } = require('./lib/store');
        const result = await atomicUpdateJSON(b.key, [], latest => {
          const latestList = Array.isArray(latest) ? latest : [];
          return latestList.filter(meta => referenced.has(String(meta?.id)));
        });
        if (result.modified) {
          for (const meta of orphaned) {
            if (meta?.blobKey) await s.delete(meta.blobKey).catch(() => {});
            orphanedFiles++;
          }
        }
      } catch (fileErr) {
        console.error('[cleanup-bans:file-reconcile]', userId, fileErr?.message || fileErr);
      }
    }
    }
    return {statusCode:200,headers:{'Cache-Control':'no-store'},body:JSON.stringify({ok:true,unbanned,orphanedFiles})};
  } catch(err) {
    return {statusCode:500,body:JSON.stringify({error:'Внутрішня помилка сервера'})};
  }
};
