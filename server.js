// r93 server initialization: encrypted at rest and session-bound after licensing.
// v88 deployment stamp: 2026-10-06 secure-session-v2
const {handleV86,operationalHealth,v88Operational,v88Lease,r93Lease,r93Health,R93_ENGINE_SEAL,r94Lease,r94Health,R94_ENGINE_SEAL,r95Lease,r95Health,R95_ENGINE_SEAL}=(()=>{
// Operational configuration is encrypted at rest; only the existing Worker signing secret can open it.
const SEALED_OPERATIONAL_CONFIG={"version":1,"salt":"dce1f1e9920b66c6d1d0760723188d2c","iv":"5b9cc4bb636adea14ff36af6","data":"gE0QRBZ+H7VYEt7uq/fzT1qJ1qejiK1eTbzNnwSdwVaTwOMZ0jgyM57UIKeXtw/9RxeJRil+fpmo+mICxBHW6BFMMxxwdzQv0WBzlPkGp0LDDgP+eA4fKfDHN8y4xhrGZXxUil1GghwEeBzIw1Tdhoz8i0pHkcxbHWoi+wUrrDXRkgQhAXFMdKxu/l6/YrT0YHkIB/T7VQW6H52cLsnrck12ruVVNYWN5NBo8qPTUwcZmfgSXfLREVkPDUModTzH8Vdw75S3yC46KJz0wfd1sNXvMyT8gghC60LrR3HqklBxqjAUvSbSJQiom58eSsPk04caXbAsiMhGqhG+ZZHKzMXft+bTe3go7GO8K8MFNU76MBF3+ett7BJflZqxXRy+s85Mw6zJ/KWMwRfR3XXTpgSmyLnJQl82ITwqw01D2G+PfEyCizNsc0Qs1LuJ42Hwgs5lTO//h/H1uo2jEO975myyA0fZd+ZQoU/lZJF+5Si5KNzN6O+ZW3sKRQFkWED+FPvSEFDETZhnRzRJOIaciFHFqhwCGGd9xh+9S/bCVpziivSMy/A5/LF2VItzLS3Afs9Gw0ZFp6R9vNQmdzhnsS7NSyZnYTrOb+1pHWJa55fj9Yyhct7l12j6oPRQ5Op90qlhxiZr8xdKVi+tSoJaoQkbjyvzXBJm9+LihVUtCfG9Igh3HpO8y1N9iMgpq76U4pFfLfgrzhiFTPCRd9h8fTwIL6FguOUJ/UVufjS+nCdO0zEPybuBkvlFBASniPk9v1i8HgO5/J2dtiRWoHlh+yTtgB7kROqgRcE13chfLuvD9zXN67NnoAuCOpqFjhAsakvz7/A/eHNBmNyRoD3wdrK1V7NU8dmhx5NtSjWHWoCC2UJKlUCnOXcfFZmJihEjybA2wP7sHgHXVhp3DM6kyD7W4FBFXaJpg84rSA8QA+anEQn7VgwFflhN2OLHar6Su1r7ro/a8IJdjLcms4sXoFbIK/tCeE0bBXsWx+KOaTCEMg22uL3pVSZxPR5arwQLeiqrgJvYI5ak3ICMzLuRJzlfOP3qwLDpf/dGEB0436QwYN5pScxzrxNHRUyoA3sKhjUOIiXiYJihlSdJewXMna/yIxiSA6ElxE5brnZGyCgD9xthCIs8pAa/5dUw3SGQqZTJe9gnpCjbmQ=="};
const COUNT=65,START=216,SIZE=START+COUNT*8;
const encoder=new TextEncoder();
const headers={'Content-Type':'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(status,body=null)=>new Response(body,{status,headers:body?{...headers,'Content-Length':String(body.byteLength)}:headers});
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
function unhex(s,n){if(typeof s!=='string'||!new RegExp(`^[0-9a-f]{${n*2}}$`).test(s))throw Error('hex');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));}
async function digest(s){return new Uint8Array(await crypto.subtle.digest('SHA-256',typeof s==='string'?encoder.encode(s):s));}
function uint(n,max=0xfffffff){if(!Number.isSafeInteger(n)||n<=0||n>max)throw Error('integer');return n;}
function operationBytes(c){const b=new Uint8Array(COUNT*8),v=new DataView(b.buffer);c.operations.forEach((x,i)=>v.setBigUint64(i*8,BigInt(x),true));return b;}
async function validateConfig(c){
  if(!c||c.schema!==2||!Array.isArray(c.operations)||c.operations.length!==COUNT)throw Error('configuration');
  unhex(c.build_id,16);const uuid=unhex(c.runtime_uuid,16);if(!uuid.some(x=>x))throw Error('uuid');
  unhex(c.public_key_x963,65);unhex(c.operations_sha256,32);
  if(uint(c.seed_vm)%4||uint(c.ready_vm)%4||c.seed_vm===c.ready_vm)throw Error('entry');
  c.operations.forEach((x,i)=>uint(x,i>=36&&i<64?0x10000:0xfffffff));
  if(c.operations[64]!==180||hex(await digest(operationBytes(c)))!==c.operations_sha256)throw Error('operations');
  return c;
}
function signatureDER(raw){
  const b=new Uint8Array(raw);if(b.length!==64)throw Error('signature');
  const integer=p=>{let i=0;while(i<31&&p[i]===0)i++;p=p.slice(i);return [...(p[0]&128?[0]:[]),...p];};
  const r=integer(b.slice(0,32)),s=integer(b.slice(32));return new Uint8Array([0x30,4+r.length+s.length,2,r.length,...r,2,s.length,...s]);
}
async function unsealOperational(der){
  const sealed=SEALED_OPERATIONAL_CONFIG;
  if(sealed.version!==1)throw Error('sealed configuration');
  const info=encoder.encode('REAPER v86 server operational config HKDF-SHA256 AES-256-GCM v1');
  const material=await crypto.subtle.importKey('raw',der,'HKDF',false,['deriveKey']);
  const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(sealed.salt,16),info},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const cipher=Uint8Array.from(atob(sealed.data),x=>x.charCodeAt(0));
  if(cipher.length<17||cipher.length>4096)throw Error('sealed size');
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(sealed.iv,12),additionalData:info,tagLength:128},aes,cipher);
  return new TextDecoder('utf-8',{fatal:true}).decode(plain);
}
let cachedJSON,cachedPEM,cachedSettings;
async function settings(env){
  const config=env.REAPER_OPERATIONAL_JSON,pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(!pem||!env.DB||(config!==undefined&&!config))throw Error('configuration');
  const source=config===undefined?'sealed:'+SEALED_OPERATIONAL_CONFIG.data:config;
  if(cachedSettings&&cachedJSON===source&&cachedPEM===pem)return cachedSettings;
  if(!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('key');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const c=await validateConfig(JSON.parse(config===undefined?await unsealOperational(der):config));
  const key=await crypto.subtle.importKey('pkcs8',der,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const pub=await crypto.subtle.importKey('raw',unhex(c.public_key_x963,65),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const probe=encoder.encode('Reaper v86 operational identity');
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,probe);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,sig,probe))throw Error('identity');
  cachedJSON=source;cachedPEM=pem;cachedSettings={c,key};return cachedSettings;
}
async function makeOperationalCapsule(c,key,body,issued,expiry){
  const b=new Uint8Array(SIZE),v=new DataView(b.buffer);
  const put=(o,x)=>b.set(x,o),u32=(o,x)=>v.setUint32(o,x,true),u64=(o,x)=>v.setBigUint64(o,BigInt(x),true);
  put(0,encoder.encode('R86BOOT1'));u32(8,2);u32(12,COUNT);put(16,unhex(c.build_id,16));put(32,unhex(body.nonce,32));
  put(64,await digest(body.device_id));put(96,await digest(body.key));u64(128,issued);u64(136,Math.min(issued+120,expiry));
  u64(144,expiry);u64(152,c.seed_vm);u64(160,c.ready_vm);put(168,unhex(c.runtime_uuid,16));
  put(184,unhex(c.operations_sha256,32));put(START,operationBytes(c));
  const sig=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,b));
  const result=new Uint8Array(SIZE+4+sig.length);result.set(b);new DataView(result.buffer).setUint32(SIZE,sig.length,true);result.set(sig,SIZE+4);return result;
}
async function boundedJSON(request){
  const declared=request.headers.get('Content-Length');
  if(declared!==null&&(!/^\d+$/.test(declared)||Number(declared)>1024))throw Error('length');
  if(!request.body)throw Error('body');const reader=request.body.getReader();let size=0,chunks=[];
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>1024){await reader.cancel();throw Error('length');}chunks.push(value);}}
  finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let p=0;for(const chunk of chunks){bytes.set(chunk,p);p+=chunk.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
function validRequest(b){
  return b&&!Array.isArray(b)&&typeof b==='object'&&Object.keys(b).sort().join(',')==='build_id,device_id,key,nonce'&&
    typeof b.key==='string'&&/^[A-Z0-9-]{8,80}$/.test(b.key)&&typeof b.device_id==='string'&&/^[A-Za-z0-9-]{1,180}$/.test(b.device_id)&&
    typeof b.nonce==='string'&&/^[0-9a-f]{64}$/.test(b.nonce)&&typeof b.build_id==='string'&&/^[0-9a-f]{32}$/.test(b.build_id);
}
async function handleV86(request,env,verify){
  const url=new URL(request.url);if(!url.pathname.startsWith('/v86/'))return null;
  if(url.search)return reply(400);if(url.pathname!=='/v86/bootstrap')return reply(404);if(request.method!=='POST')return reply(405);
  let body;try{body=await boundedJSON(request);if(!validRequest(body))return reply(403);}catch{return reply(403);}
  try{
    const {c,key}=await settings(env);if(body.build_id!==c.build_id)return reply(403);
    const auth=await verify(body.key,body.device_id);
    if(!auth||auth.ok!==true||typeof auth.expires_at!=='string'||!/(Z|[+-]\d{2}:\d{2})$/.test(auth.expires_at))return reply(403);
    const now=Math.floor(Date.now()/1000),expiry=Math.floor(Date.parse(auth.expires_at)/1000);
    if(!Number.isSafeInteger(expiry)||expiry<=now)return reply(403);
    const id=hex(await digest('v86\0'+c.build_id+'\0'+body.device_id+'\0'+body.key+'\0'+body.nonce));
    await env.DB.prepare('DELETE FROM reaper_v85_nonces WHERE expires <= ?').bind(now).run();
    const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_v85_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_v85_nonces) < 4096').bind(id,Math.min(now+120,expiry)).run();
    if(used.meta?.changes!==1)return reply(403);
    return reply(200,await makeOperationalCapsule(c,key,body,now,expiry));
  }catch{return reply(503);}
}
async function operationalHealth(env){
  const result={configured:Boolean(env.DB&&env.REAPER_SIGNING_KEY_PKCS8&&(env.REAPER_OPERATIONAL_JSON===undefined||env.REAPER_OPERATIONAL_JSON)),signing_valid:false,operations_ready:false,database_ready:false};
  if(!result.configured)return result;
  try{await settings(env);result.signing_valid=result.operations_ready=true;}catch{return result;}
  try{await env.DB.prepare('SELECT identity FROM reaper_v85_nonces LIMIT 1').all();result.database_ready=true;}catch{}
  return result;
}


const V88_BUILD_ID='474e5df98fbd09aa825a186d8bb87a41';
function v88Hex64(values){
  return values.map(v=>BigInt(v).toString(16).padStart(16,'0')).join('');
}
async function v88Operational(env){
  const {c}=await settings(env);
  if(!Array.isArray(c.operations)||c.operations.length!==65)throw Error('v88 operations');
  // c.operations[64] is the legacy v86 startup timeout, not LegacyAimState.
  // v88 keeps only indices 0..63 from v86, then inserts the server-owned LegacyAimState
  // before the new draw/ESP fields and the final startup timeout.
  const values=[...c.operations.slice(0,64),93633800,57697588,40,36,44,28,c.operations[32],180];
  if(values.length!==72)throw Error('v88 count');
  return v88Hex64(values);
}
function v88U32(out,off,v){
  const d=new DataView(out.buffer,out.byteOffset,out.byteLength);d.setUint32(off,v,true);
}
function v88U64(out,off,v){
  const d=new DataView(out.buffer,out.byteOffset,out.byteLength);d.setBigUint64(off,BigInt(v),true);
}
async function v88Lease(env,req,licenseExpiry){
  if(!req||req.protocol!=='r88'||req.build_id!==V88_BUILD_ID||typeof req.nonce!=='string'||!/^[0-9a-f]{64}$/.test(req.nonce))throw Error('v88 request');
  if(typeof req.device_id!=='string'||typeof req.key!=='string')throw Error('v88 identity');
  const {key}=await settings(env);
  const operational=await v88Operational(env);
  const now=Math.floor(Date.now()/1000), exp=Math.min(now+180,licenseExpiry);
  if(!Number.isSafeInteger(licenseExpiry)||exp<=now)throw Error('v88 expiry');
  const msg=new Uint8Array(180);
  msg.set(encoder.encode('R88SESS1'),0);v88U32(msg,8,1);
  msg.set(unhex(V88_BUILD_ID,16),12);msg.set(unhex(req.nonce,32),28);
  msg.set(await digest(req.device_id),60);msg.set(await digest(req.key),92);
  v88U64(msg,124,now);v88U64(msg,132,exp);v88U64(msg,140,licenseExpiry);
  msg.set(await digest(operational),148);
  const raw=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,msg);
  const der=signatureDER(raw);
  return {
    operational,
    session_nonce:req.nonce,
    session_issued:now,
    session_expires:exp,
    session_signature:hex(der)
  };
}


const R93_ENGINE_SEAL={"version":1,"build_id":"90b9a730b9cc83766a4bc7451e675aa5","program_sha256":"1959b5d0889e20b90cd5d19a26d3dc44ebb6ff2989e67e776e5b1db9a745c34b","program_size":1890,"ephemeral_public_x963":"04dd0799d7e47fe151bf32353ae508265c84d61b27051972a62da58b9e904296daad269b6670a3f60ff1e9403a0215fa11aa9a8a12c23cb876932db90f5f2f4aa3","salt":"da518750054c918777017e7dba9dc0658a6a749265f44daf3f75e2c8dbb49d9b","iv":"295565ca5d10038d1385d726","data":"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"};
const R93_ENGINE_INFO='REAPER r93 server initialization engine ECDH HKDF-SHA256 AES-256-GCM v1';
let r93CachedPEM,r93CachedEngine;
async function r93OpenEngine(env){
  const pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(r93CachedEngine&&r93CachedPEM===pem)return r93CachedEngine;
  if(typeof pem!=='string'||!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('r93 signing');
  const s=R93_ENGINE_SEAL;
  if(s.version!==1||!Number.isSafeInteger(s.program_size)||s.program_size<48||s.program_size>4096)throw Error('r93 size');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const own=await crypto.subtle.importKey('pkcs8',der,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const peer=await crypto.subtle.importKey('raw',unhex(s.ephemeral_public_x963,65),{name:'ECDH',namedCurve:'P-256'},false,[]);
  const shared=await crypto.subtle.deriveBits({name:'ECDH',public:peer},own,256);
  const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
  const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(s.salt,32),info:encoder.encode(R93_ENGINE_INFO)},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const aad=encoder.encode(R93_ENGINE_INFO+'\0'+s.build_id+'\0'+s.program_sha256);
  const cipher=Uint8Array.from(atob(s.data),x=>x.charCodeAt(0));
  if(cipher.length!==s.program_size+16)throw Error('r93 cipher');
  const p=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(s.iv,12),additionalData:aad,tagLength:128},aes,cipher));
  if(p.length!==s.program_size||hex(await digest(p))!==s.program_sha256)throw Error('r93 engine hash');
  const v=new DataView(p.buffer,p.byteOffset,p.byteLength),count=v.getUint32(12,true),data=v.getUint32(24,true);
  if(new TextDecoder().decode(p.slice(0,8))!=='R93INIT1'||v.getUint32(8,true)!==1||!count||count>192||data!==32+16*count||data>=p.length||v.getUint32(28,true)!==p.length||v.getUint32(16,true)>=count||v.getUint32(20,true)>=count)throw Error('r93 program');
  r93CachedPEM=pem;r93CachedEngine=p;return p;
}
async function r93Lease(env,req,licenseExpiry){
  if(!req||req.protocol!=='r93'||req.build_id!==R93_ENGINE_SEAL.build_id||typeof req.nonce!=='string'||!/^[0-9a-f]{64}$/.test(req.nonce)||typeof req.device_id!=='string'||!/^[A-Za-z0-9-]{1,180}$/.test(req.device_id)||typeof req.key!=='string')throw Error('r93 request');
  const {key}=await settings(env),engine=await r93OpenEngine(env),operational=await v88Operational(env);
  const now=Math.floor(Date.now()/1000),exp=Math.min(now+180,licenseExpiry);
  if(!Number.isSafeInteger(licenseExpiry)||exp<=now)throw Error('r93 expiry');
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS reaper_r93_nonces (identity TEXT PRIMARY KEY, expires INTEGER NOT NULL)').run();
  await env.DB.prepare('DELETE FROM reaper_r93_nonces WHERE expires <= ?').bind(now).run();
  const identity=hex(await digest('r93\0'+req.build_id+'\0'+req.key+'\0'+req.device_id+'\0'+req.nonce));
  const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_r93_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_r93_nonces) < 4096').bind(identity,exp).run();
  if(used.meta?.changes!==1)throw Error('r93 replay');
  const msg=new Uint8Array(212);
  msg.set(encoder.encode('R93SESS1'));v88U32(msg,8,1);
  msg.set(unhex(req.build_id,16),12);msg.set(unhex(req.nonce,32),28);
  msg.set(await digest(req.device_id),60);msg.set(await digest(req.key),92);
  v88U64(msg,124,now);v88U64(msg,132,exp);v88U64(msg,140,licenseExpiry);
  msg.set(await digest(operational),148);msg.set(await digest(engine),180);
  const signature=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,msg));
  return {operational,engine:hex(engine),engine_sha256:hex(await digest(engine)),session_nonce:req.nonce,session_issued:now,session_expires:exp,session_signature:hex(signature)};
}
async function r93Health(env){
  const result={protocol:'r93',build_id:R93_ENGINE_SEAL.build_id,program_sha256:R93_ENGINE_SEAL.program_sha256,program_ready:false};
  try{await settings(env);await r93OpenEngine(env);result.program_ready=true;}catch{}
  return result;
}

const R94_ENGINE_SEAL={"version":1,"build_id":"187f6d90bfffc10d69fa8475731d4aff","program_sha256":"24c5804b9ad098f10b8c4ddd5fc039a08f590f7dccb930e43e48d7e31a91b4cc","program_size":44448,"ephemeral_public_x963":"0446a0a6ef0e06007dc73e4ff415c76db99650a805c59a2e020e20fa3dd76b0bb05b37f1408b393134ac9505842faa8881ab684a210ff840efc2cfbc3a3bc12e3b","salt":"1c1cc8c8ccc20177323fc7c2e9d63e23cf8665edaec928912023725666c05d86","iv":"6e5bc08b6b39b02934b78546","data":"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"};
const R94_ENGINE_INFO='REAPER r94 server menu initialization engine ECDH HKDF-SHA256 AES-256-GCM v1';
let r94CachedPEM,r94CachedEngine;
async function r94OpenEngine(env){
  const pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(r94CachedEngine&&r94CachedPEM===pem)return r94CachedEngine;
  if(typeof pem!=='string'||!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('r94 signing');
  const s=R94_ENGINE_SEAL;
  if(s.version!==1||!Number.isSafeInteger(s.program_size)||s.program_size<48||s.program_size>65536)throw Error('r94 size');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const own=await crypto.subtle.importKey('pkcs8',der,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const peer=await crypto.subtle.importKey('raw',unhex(s.ephemeral_public_x963,65),{name:'ECDH',namedCurve:'P-256'},false,[]);
  const shared=await crypto.subtle.deriveBits({name:'ECDH',public:peer},own,256);
  const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
  const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(s.salt,32),info:encoder.encode(R94_ENGINE_INFO)},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const aad=encoder.encode(R94_ENGINE_INFO+'\0'+s.build_id+'\0'+s.program_sha256);
  const cipher=Uint8Array.from(atob(s.data),x=>x.charCodeAt(0));
  if(cipher.length!==s.program_size+16)throw Error('r94 cipher');
  const p=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(s.iv,12),additionalData:aad,tagLength:128},aes,cipher));
  if(p.length!==s.program_size||hex(await digest(p))!==s.program_sha256)throw Error('r94 engine hash');
  const v=new DataView(p.buffer,p.byteOffset,p.byteLength),count=v.getUint32(12,true),data=v.getUint32(36,true);
  if(new TextDecoder().decode(p.slice(0,8))!=='R94INIT1'||v.getUint32(8,true)!==2||!count||count>4096||data!==48+16*count||data>=p.length||v.getUint32(40,true)!==p.length||v.getUint32(44,true))throw Error('r94 program');
  for(let j=0;j<5;j++)if(v.getUint32(16+j*4,true)>=count)throw Error('r94 entry');
  r94CachedPEM=pem;r94CachedEngine=p;return p;
}
async function r94Lease(env,req,licenseExpiry){
  if(!req||req.protocol!=='r94'||req.build_id!==R94_ENGINE_SEAL.build_id||typeof req.nonce!=='string'||!/^[0-9a-f]{64}$/.test(req.nonce)||typeof req.device_id!=='string'||!/^[A-Za-z0-9-]{1,180}$/.test(req.device_id)||typeof req.key!=='string')throw Error('r94 request');
  const {key}=await settings(env),engine=await r94OpenEngine(env),operational=await v88Operational(env);
  const now=Math.floor(Date.now()/1000),exp=Math.min(now+180,licenseExpiry);
  if(!Number.isSafeInteger(licenseExpiry)||exp<=now)throw Error('r94 expiry');
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS reaper_r94_nonces (identity TEXT PRIMARY KEY, expires INTEGER NOT NULL)').run();
  await env.DB.prepare('DELETE FROM reaper_r94_nonces WHERE expires <= ?').bind(now).run();
  const identity=hex(await digest('r94\0'+req.build_id+'\0'+req.key+'\0'+req.device_id+'\0'+req.nonce));
  const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_r94_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_r94_nonces) < 4096').bind(identity,exp).run();
  if(used.meta?.changes!==1)throw Error('r94 replay');
  const msg=new Uint8Array(212);
  msg.set(encoder.encode('R94SESS1'));v88U32(msg,8,1);
  msg.set(unhex(req.build_id,16),12);msg.set(unhex(req.nonce,32),28);
  msg.set(await digest(req.device_id),60);msg.set(await digest(req.key),92);
  v88U64(msg,124,now);v88U64(msg,132,exp);v88U64(msg,140,licenseExpiry);
  msg.set(await digest(operational),148);msg.set(await digest(engine),180);
  const signature=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,msg));
  return {operational,engine:hex(engine),engine_sha256:hex(await digest(engine)),session_nonce:req.nonce,session_issued:now,session_expires:exp,session_signature:hex(signature)};
}
async function r94Health(env){
  const result={protocol:'r94',build_id:R94_ENGINE_SEAL.build_id,program_sha256:R94_ENGINE_SEAL.program_sha256,program_ready:false};
  try{await settings(env);await r94OpenEngine(env);result.program_ready=true;}catch{}
  return result;
}

const R95_ENGINE_SEAL={"version":1,"build_id":"6de243d8ba8fca1bb3e81d94c6a4ac27","program_sha256":"03e51a8ff761bedc3779ca5a8d7a9deaccfff7344f35ee28120ffe5461b45333","program_size":54760,"ephemeral_public_x963":"04f0788ccc73670582963875378ec2c038199ec694d8179c534d0d9ff895a41d74c122d15bf96cf92f812c555b21dd2cd57bbcfe7bb24374348d146438d4dd2ee6","salt":"04641d5cb5f7ad2a783f395e370899e86cd40856d85aa992fa80d06f2b34a46d","iv":"a616f8a1917f2f29bee0c264","data":"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"};
const R95_ENGINE_INFO='REAPER r95 server menu initialization engine ECDH HKDF-SHA256 AES-256-GCM v1';
let r95CachedPEM,r95CachedEngine;
async function r95OpenEngine(env){
  const pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(r95CachedEngine&&r95CachedPEM===pem)return r95CachedEngine;
  if(typeof pem!=='string'||!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('r95 signing');
  const s=R95_ENGINE_SEAL;
  if(s.version!==1||!Number.isSafeInteger(s.program_size)||s.program_size<48||s.program_size>65536)throw Error('r95 size');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const own=await crypto.subtle.importKey('pkcs8',der,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const peer=await crypto.subtle.importKey('raw',unhex(s.ephemeral_public_x963,65),{name:'ECDH',namedCurve:'P-256'},false,[]);
  const shared=await crypto.subtle.deriveBits({name:'ECDH',public:peer},own,256);
  const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
  const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(s.salt,32),info:encoder.encode(R95_ENGINE_INFO)},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const aad=encoder.encode(R95_ENGINE_INFO+'\0'+s.build_id+'\0'+s.program_sha256);
  const cipher=Uint8Array.from(atob(s.data),x=>x.charCodeAt(0));
  if(cipher.length!==s.program_size+16)throw Error('r95 cipher');
  const p=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(s.iv,12),additionalData:aad,tagLength:128},aes,cipher));
  if(p.length!==s.program_size||hex(await digest(p))!==s.program_sha256)throw Error('r95 engine hash');
  const v=new DataView(p.buffer,p.byteOffset,p.byteLength),count=v.getUint32(12,true),data=v.getUint32(36,true);
  if(new TextDecoder().decode(p.slice(0,8))!=='R95INIT1'||v.getUint32(8,true)!==2||!count||count>4096||data!==48+16*count||data>=p.length||v.getUint32(40,true)!==p.length||v.getUint32(44,true))throw Error('r95 program');
  for(let j=0;j<5;j++)if(v.getUint32(16+j*4,true)>=count)throw Error('r95 entry');
  r95CachedPEM=pem;r95CachedEngine=p;return p;
}
async function r95Lease(env,req,licenseExpiry){
  if(!req||req.protocol!=='r95'||req.build_id!==R95_ENGINE_SEAL.build_id||typeof req.nonce!=='string'||!/^[0-9a-f]{64}$/.test(req.nonce)||typeof req.device_id!=='string'||!/^[A-Za-z0-9-]{1,180}$/.test(req.device_id)||typeof req.key!=='string')throw Error('r95 request');
  const {key}=await settings(env),engine=await r95OpenEngine(env),operational=await v88Operational(env);
  const now=Math.floor(Date.now()/1000),exp=Math.min(now+180,licenseExpiry);
  if(!Number.isSafeInteger(licenseExpiry)||exp<=now)throw Error('r95 expiry');
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS reaper_r95_nonces (identity TEXT PRIMARY KEY, expires INTEGER NOT NULL)').run();
  await env.DB.prepare('DELETE FROM reaper_r95_nonces WHERE expires <= ?').bind(now).run();
  const identity=hex(await digest('r95\0'+req.build_id+'\0'+req.key+'\0'+req.device_id+'\0'+req.nonce));
  const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_r95_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_r95_nonces) < 4096').bind(identity,exp).run();
  if(used.meta?.changes!==1)throw Error('r95 replay');
  const msg=new Uint8Array(212);
  msg.set(encoder.encode('R95SESS1'));v88U32(msg,8,1);
  msg.set(unhex(req.build_id,16),12);msg.set(unhex(req.nonce,32),28);
  msg.set(await digest(req.device_id),60);msg.set(await digest(req.key),92);
  v88U64(msg,124,now);v88U64(msg,132,exp);v88U64(msg,140,licenseExpiry);
  msg.set(await digest(operational),148);msg.set(await digest(engine),180);
  const signature=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,msg));
  return {operational,engine:hex(engine),engine_sha256:hex(await digest(engine)),session_nonce:req.nonce,session_issued:now,session_expires:exp,session_signature:hex(signature)};
}
async function r95Health(env){
  const result={protocol:'r95',build_id:R95_ENGINE_SEAL.build_id,program_sha256:R95_ENGINE_SEAL.program_sha256,program_ready:false};
  try{await settings(env);await r95OpenEngine(env);result.program_ready=true;}catch{}
  return result;
}

return {handleV86,operationalHealth,v88Operational,v88Lease,r93Lease,r93Health,R93_ENGINE_SEAL,r94Lease,r94Health,R94_ENGINE_SEAL,r95Lease,r95Health,R95_ENGINE_SEAL};
})();
const worker = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const verifyBootstrap = async (key, device_id) => {
      const verifyURL = new URL('/v1/license/verify', request.url);
      const response = await worker.fetch(new Request(verifyURL, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key, device_id})
      }), env);
      return response.ok ? response.json() : null;
    };
    const operational = await handleV86(request, env, verifyBootstrap);
    if (operational) return operational;
    const bootstrap = await handleV85(request, env, verifyBootstrap);
    if (bootstrap) return bootstrap;

    if (
      request.method === "GET" &&
      !url.pathname.startsWith("/v1/") &&
      url.pathname !== "/health"
    ) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      const maintenance = await getMaintenance(env);
      return json({
        ok: true,
        service: "vip-reaper",
        admin_token_configured: Boolean(env.ADMIN_TOKEN),
        maintenance: maintenance.enabled,
        bootstrap: await bootstrapHealth(env),
        operational: await operationalHealth(env),
        initialization: await r93Health(env),
        menu_initialization: await r94Health(env),
        single_menu_initialization: await r95Health(env)
      });
    }

    async function admin(req) {
      const auth = req.headers.get("Authorization") || "";
      const token = auth.replace(/^Bearer\s+/i, "");
      return Boolean(
        env.ADMIN_TOKEN &&
        token.trim() === env.ADMIN_TOKEN.trim()
      );
    }

    // ==========================================
    // Maintenance - قراءة حالة السيرفر
    // ==========================================
    if (
      url.pathname === "/v1/admin/maintenance" &&
      request.method === "GET"
    ) {
      if (!(await admin(request))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }

      const maintenance = await getMaintenance(env);

      return json({
        ok: true,
        ...maintenance
      });
    }

    // ==========================================
    // Maintenance - تشغيل / إيقاف
    // ==========================================
    if (
      url.pathname === "/v1/admin/maintenance" &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }

      try {
        const body = await request.json();

        if (typeof body?.enabled !== "boolean") {
          return json(
            {
              ok: false,
              error: "invalid_maintenance_state"
            },
            400
          );
        }

        const message =
          typeof body?.message === "string" &&
          body.message.trim()
            ? body.message.trim().slice(0, 500)
            : MAINTENANCE_MESSAGE;

        await ensureSettings(env);

        await env.DB.prepare(
          `INSERT INTO server_settings
           (name,value,updated_at)
           VALUES
           ('maintenance_enabled',?,datetime('now'))
           ON CONFLICT(name)
           DO UPDATE SET
           value=excluded.value,
           updated_at=datetime('now')`
        )
          .bind(body.enabled ? "1" : "0")
          .run();

        await env.DB.prepare(
          `INSERT INTO server_settings
           (name,value,updated_at)
           VALUES
           ('maintenance_message',?,datetime('now'))
           ON CONFLICT(name)
           DO UPDATE SET
           value=excluded.value,
           updated_at=datetime('now')`
        )
          .bind(message)
          .run();

        return json({
          ok: true,
          enabled: body.enabled,
          message
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // ==========================================
    // التحقق من المفتاح
    // ==========================================
    if (
      url.pathname === "/v1/license/verify" &&
      request.method === "POST"
    ) {
      try {
        // أولاً نفحص حالة الصيانة
        const maintenance = await getMaintenance(env);

        if (maintenance.enabled) {
          return json(
            {
              ok: false,
              maintenance: true,
              error: "maintenance",
              message: maintenance.message
            },
            503
          );
        }

        await cleanupExpired(env);

        const body = await boundedJSON(request);
        if (body?.protocol === "r93" && (body.build_id !== R93_ENGINE_SEAL.build_id || typeof body.nonce !== "string" || !/^[0-9a-f]{64}$/.test(body.nonce))) {
          return json({ok:false,error:"invalid_secure_session"},403);
        }

        if (body?.protocol === "r94" && (body.build_id !== R94_ENGINE_SEAL.build_id || typeof body.nonce !== "string" || !/^[0-9a-f]{64}$/.test(body.nonce))) {
          return json({ok:false,error:"invalid_secure_session"},403);
        }

        if (body?.protocol === "r95" && (body.build_id !== R95_ENGINE_SEAL.build_id || typeof body.nonce !== "string" || !/^[0-9a-f]{64}$/.test(body.nonce))) {
          return json({ok:false,error:"invalid_secure_session"},403);
        }

        const key = body?.key;

        const deviceId =
          typeof body?.device_id === "string"
            ? body.device_id.trim()
            : "";

        if (!isValidKey(key)) {
          return json(
            {
              ok: false,
              error: "invalid_key"
            },
            400
          );
        }

        const row = await env.DB.prepare(
          `SELECT
             key,
             status,
             expires_at,
             device_mode,
             device_hash,
             created_at,
             last_seen_at
           FROM licenses
           WHERE key=?`
        )
          .bind(key)
          .first();

        if (!row) {
          return json(
            {
              ok: false,
              error: "invalid_license"
            },
            404
          );
        }

        if (row.status !== "active") {
          return json(
            {
              ok: false,
              error: "license_" + row.status
            },
            403
          );
        }

        if (
          row.expires_at &&
          new Date(row.expires_at) <= new Date()
        ) {
          await env.DB.prepare(
            "UPDATE licenses SET status='expired' WHERE key=?"
          )
            .bind(key)
            .run();

          return json(
            {
              ok: false,
              error: "license_expired"
            },
            403
          );
        }

        let boundNow = false;

        if (row.device_mode === "single_device") {
          if (!deviceId) {
            return json(
              {
                ok: false,
                error: "device_id_required"
              },
              400
            );
          }

          const hash = await sha256(deviceId);

          if (!row.device_hash) {
            await env.DB.prepare(
              `UPDATE licenses
               SET device_hash=?,
                   last_seen_at=datetime('now')
               WHERE key=? AND device_hash IS NULL`
            )
              .bind(hash, key)
              .run();

            const binding = await env.DB.prepare(
              "SELECT device_hash FROM licenses WHERE key=?"
            ).bind(key).first();
            if (!binding || binding.device_hash !== hash) {
              return json({ok: false, error: "device_mismatch"}, 403);
            }
            row.device_hash = binding.device_hash;
            boundNow = true;
          } else if (row.device_hash !== hash) {
            return json(
              {
                ok: false,
                error: "device_mismatch"
              },
              403
            );
          }
        }

        await env.DB.prepare(
          `UPDATE licenses
           SET last_seen_at=datetime('now')
           WHERE key=?`
        )
          .bind(key)
          .run();

        let secure = { operational: await v88Operational(env) };
        if (body?.protocol === "r88" || body?.protocol === "r93" || body?.protocol === "r94" || body?.protocol === "r95") {
          const licenseExpiry = Math.floor(Date.parse(row.expires_at) / 1000);
          try {
            secure = await (body.protocol === "r95" ? r95Lease : body.protocol === "r94" ? r94Lease : body.protocol === "r93" ? r93Lease : v88Lease)(env, {
              protocol: body.protocol,
              build_id: body.build_id,
              nonce: body.nonce,
              device_id: deviceId,
              key
            }, licenseExpiry);
          } catch {
            return json({ ok: false, error: "invalid_secure_session" }, 403);
          }
        }

        return json({
          ok: true,
          key: row.key,
          expires_at: row.expires_at,
          device_mode: row.device_mode,
          device_bound: Boolean(row.device_hash),
          bound_now: boundNow,
          ...secure
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // حذف المفاتيح المنتهية
    await cleanupExpired(env);

    // ==========================================
    // عرض المفاتيح + البحث
    // مثال:
    // /v1/admin/licenses?q=ABC
    // ==========================================
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "GET"
    ) {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      const q = (
        url.searchParams.get("q") || ""
      )
        .trim()
        .toUpperCase();

      let stmt;

      if (q) {
        stmt = env.DB.prepare(
          `SELECT
             id,
             key,
             status,
             expires_at,
             created_at,
             last_seen_at,
             device_mode,
             CASE
               WHEN device_hash IS NULL THEN 0
               ELSE 1
             END AS device_bound,
             duration_value,
             duration_unit
           FROM licenses
           WHERE UPPER(key) LIKE ?
           ORDER BY id DESC`
        ).bind("%" + q + "%");
      } else {
        stmt = env.DB.prepare(
          `SELECT
             id,
             key,
             status,
             expires_at,
             created_at,
             last_seen_at,
             device_mode,
             CASE
               WHEN device_hash IS NULL THEN 0
               ELSE 1
             END AS device_bound,
             duration_value,
             duration_unit
           FROM licenses
           ORDER BY id DESC`
        );
      }

      const result = await stmt.all();

      return json({
        ok: true,
        licenses: result.results || []
      });
    }

    // ==========================================
    // إنشاء مفتاح
    // ==========================================
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      try {
        const body = await request.json();

        const value = Number(body?.duration_value);

        const unit =
          body?.duration_unit === "days"
            ? "days"
            : "hours";

        const mode =
          body?.device_mode === "unlimited_devices"
            ? "unlimited_devices"
            : "single_device";

        if (
          !Number.isInteger(value) ||
          value < 1 ||
          value >
            (unit === "days" ? 3650 : 87600)
        ) {
          return json(
            {
              ok: false,
              error: "invalid_duration"
            },
            400
          );
        }

        const key = makeKey();

        const ms =
          value *
          (unit === "days"
            ? 86400000
            : 3600000);

        const expires =
          new Date(
            Date.now() + ms
          ).toISOString();

        await env.DB.prepare(
          `INSERT INTO licenses
           (
             key,
             status,
             expires_at,
             device_mode,
             device_hash,
             duration_value,
             duration_unit
           )
           VALUES
           (?,'active',?,?,NULL,?,?)`
        )
          .bind(
            key,
            expires,
            mode,
            value,
            unit
          )
          .run();

        return json({
          ok: true,
          key,
          expires_at: expires,
          device_mode: mode,
          duration_value: value,
          duration_unit: unit
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // ==========================================
    // إدارة مفتاح محدد
    // ==========================================
    const m = url.pathname.match(
      /^\/v1\/admin\/licenses\/([^/]+)\/(revoke|activate|reset-device|reset-license|delete)$/
    );

    if (m && request.method === "POST") {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      const key =
        decodeURIComponent(m[1]);

      const action = m[2];

      // إيقاف مفتاح
      if (action === "revoke") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET status='revoked'
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // تفعيل مفتاح
      if (action === "activate") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET status='active'
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // Reset Device
      if (action === "reset-device") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET device_hash=NULL,
                 last_seen_at=NULL
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // Reset License
      if (action === "reset-license") {
        const row =
          await env.DB.prepare(
            `SELECT
               duration_value,
               duration_unit
             FROM licenses
             WHERE key=?`
          )
            .bind(key)
            .first();

        if (!row) {
          return json(
            {
              ok: false,
              error: "invalid_license"
            },
            404
          );
        }

        const ms =
          Number(row.duration_value) *
          (
            row.duration_unit === "days"
              ? 86400000
              : 3600000
          );

        const expires =
          new Date(
            Date.now() + ms
          ).toISOString();

        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET
               status='active',
               expires_at=?,
               device_hash=NULL,
               last_seen_at=NULL
             WHERE key=?`
          )
            .bind(
              expires,
              key
            )
            .run();

        return json({
          ok: r.meta?.changes === 1,
          expires_at: expires
        });
      }

      // حذف
      if (action === "delete") {
        const r =
          await env.DB.prepare(
            "DELETE FROM licenses WHERE key=?"
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }
    }

    return json(
      {
        ok: false,
        error: "not_found"
      },
      404
    );
  },

  // Cron cleanup
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      cleanupExpired(env)
    );
  }
};


// ==========================================
// رسالة الصيانة
// ==========================================

const MAINTENANCE_MESSAGE =
  "السيرفر قيد الصيانة، الرجاء التحلي بالصبر حتى يتم إضافة الإصلاحات";


// ==========================================
// إنشاء جدول إعدادات السيرفر تلقائياً
// ==========================================

async function ensureSettings(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS server_settings (
       name TEXT PRIMARY KEY,
       value TEXT NOT NULL,
       updated_at TEXT DEFAULT (datetime('now'))
     )`
  ).run();
}


// ==========================================
// قراءة حالة الصيانة
// ==========================================

async function getMaintenance(env) {
  await ensureSettings(env);

  const result =
    await env.DB.prepare(
      `SELECT name,value
       FROM server_settings
       WHERE name IN (
         'maintenance_enabled',
         'maintenance_message'
       )`
    ).all();

  let enabled = false;

  let message =
    MAINTENANCE_MESSAGE;

  for (
    const row of result.results || []
  ) {
    if (
      row.name ===
      "maintenance_enabled"
    ) {
      enabled =
        row.value === "1";
    }

    if (
      row.name ===
        "maintenance_message" &&
      row.value
    ) {
      message = row.value;
    }
  }

  return {
    enabled,
    message
  };
}


// ==========================================
// حذف المفاتيح المنتهية
// ==========================================

async function cleanupExpired(env) {
  await env.DB.prepare(
    `UPDATE licenses
     SET status='expired'
     WHERE status='active'
     AND expires_at IS NOT NULL
     AND datetime(expires_at)
         <= datetime('now')`
  ).run();
}


// ==========================================
// SHA256
// ==========================================

async function sha256(value) {
  const data =
    new TextEncoder()
      .encode(value);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return [
    ...new Uint8Array(digest)
  ]
    .map(
      x =>
        x
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


// ==========================================
// JSON Response
// ==========================================

function json(
  data,
  status = 200
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8"
      }
    }
  );
}


// ==========================================
// إنشاء مفتاح
// ==========================================

function makeKey() {
  const bytes =
    new Uint8Array(12);

  crypto.getRandomValues(bytes);

  const hex = [
    ...bytes
  ]
    .map(
      x =>
        x
          .toString(16)
          .padStart(2, "0")
    )
    .join("")
    .toUpperCase();

  return hex
    .match(/.{1,6}/g)
    .join("-");
}


// ==========================================
// التحقق من صيغة المفتاح
// ==========================================

function isValidKey(key) {
  return (
    typeof key === "string" &&
    /^[A-Z0-9-]{8,80}$/.test(key)
  );
}

export default worker;


// Remote SDK bootstrap, wire-compatible with the existing v85 ARM64 loader.
const BUILD = '5144c274ddb8d824c6cdb506e9bedf04';
const encoder = new TextEncoder();
const headers = {'Content-Type':'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply = (status, body=null) => new Response(body,{status,headers});
const hex = b => Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
function unhex(s,n){if(typeof s!=='string'||!new RegExp(`^[0-9a-f]{${n*2}}$`).test(s))throw Error('hex');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));}
async function digest(s){return new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s)));}
function uint(n,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(n)||n<=0||n>max)throw Error('integer');return n;}
function validateCatalog(c){
  if(c.build_id!==BUILD||!Array.isArray(c.chunks)||c.chunks.length!==4)throw Error('catalog');
  uint(c.payload_size,128*1024*1024);unhex(c.payload_sha256,32);unhex(c.public_key_x963,65);
  for(const a of [c.seed_vm,c.ready_vm])if(uint(a,0xfffffff)%4)throw Error('address');
  let sum=0;
  c.chunks.forEach((e,i)=>{if(e.index!==i)throw Error('index');uint(e.plain_size,32*1024*1024);if(e.blob_size!==72+(Math.floor(e.plain_size/16)+1)*16)throw Error('size');unhex(e.sha256,32);unhex(e.keys,64);sum+=e.plain_size;});
  if(sum!==c.payload_size)throw Error('payload');return c;
}
async function settings(env){
  if(!env.REAPER_PAYLOADS||!env.DB||!env.REAPER_SIGNING_KEY_PKCS8||!env.REAPER_CATALOG_JSON)throw Error('configuration');
  const c=validateCatalog(JSON.parse(env.REAPER_CATALOG_JSON));
  const pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('key');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const key=await crypto.subtle.importKey('pkcs8',der,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const pub=await crypto.subtle.importKey('raw',unhex(c.public_key_x963,65),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  // Reject a misconfigured signing key before delivering keys to the client.
  const probe=encoder.encode('Reaper v85 signing identity');
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,probe);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,sig,probe))throw Error('identity');
  return {c,key};
}
function signatureDER(raw){
  const b=new Uint8Array(raw);if(b.length!==64)throw Error('signature');
  const integer=p=>{let i=0;while(i<31&&p[i]===0)i++;p=p.slice(i);return [...(p[0]&128?[0]:[]),...p];};
  const r=integer(b.slice(0,32)),s=integer(b.slice(32));
  return new Uint8Array([0x30,4+r.length+s.length,2,r.length,...r,2,s.length,...s]);
}
async function makeCapsule(c,key,body,issued,expiry,token){
  const b=new Uint8Array(688),v=new DataView(b.buffer);
  const put=(o,x)=>b.set(x,o),u32=(o,x)=>v.setUint32(o,x,true),u64=(o,x)=>v.setBigUint64(o,BigInt(x),true);
  put(0,encoder.encode('R85BOOT1'));u32(8,1);u32(12,4);put(16,unhex(c.build_id,16));put(32,unhex(body.nonce,32));
  put(64,await digest(body.device_id));put(96,await digest(body.key));u64(128,issued);u64(136,Math.min(issued+120,expiry));
  u64(144,c.payload_size);put(152,unhex(c.payload_sha256,32));put(184,token);u64(216,c.seed_vm);u64(224,c.ready_vm);u64(232,expiry);
  c.chunks.forEach((e,i)=>{const o=240+i*112;u32(o,i);u32(o+4,e.plain_size);u32(o+8,e.blob_size);put(o+16,unhex(e.sha256,32));put(o+48,unhex(e.keys,64));});
  const sig=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,b));
  const result=new Uint8Array(692+sig.length);result.set(b);new DataView(result.buffer).setUint32(688,sig.length,true);result.set(sig,692);return result;
}
async function boundedJSON(request){
  const declared=request.headers.get('Content-Length');
  if(declared!==null&&(!/^\d+$/.test(declared)||Number(declared)>1024))throw Error('length');
  if(!request.body)throw Error('body');const reader=request.body.getReader();let size=0,chunks=[];
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>1024){await reader.cancel();throw Error('length');}chunks.push(value);}}
  finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let p=0;for(const chunk of chunks){bytes.set(chunk,p);p+=chunk.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
function validRequest(b){
  if(!b||Array.isArray(b)||typeof b!=='object'||Object.keys(b).sort().join(',')!=='build_id,device_id,key,nonce')return false;
  return typeof b.key==='string'&&/^[A-Z0-9-]{8,80}$/.test(b.key)&&typeof b.device_id==='string'&&/^[A-Za-z0-9-]{1,180}$/.test(b.device_id)&&typeof b.nonce==='string'&&/^[0-9a-f]{64}$/.test(b.nonce)&&b.build_id===BUILD;
}
async function handleV85(request,env,verify){
  const url=new URL(request.url);if(!url.pathname.startsWith('/v85/'))return null;
  if(url.search)return reply(400);
  if(url.pathname==='/v85/bootstrap'){
    if(request.method!=='POST')return reply(405);
    let body;try{body=await boundedJSON(request);if(!validRequest(body))return reply(403);}catch{return reply(403);}
    try{
      const {c,key}=await settings(env);
      const auth=await verify(body.key,body.device_id);
      if(!auth||auth.ok!==true||typeof auth.expires_at!=='string'||!/(Z|[+-]\d{2}:\d{2})$/.test(auth.expires_at))return reply(403);
      const now=Math.floor(Date.now()/1000),expiry=Math.floor(Date.parse(auth.expires_at)/1000);
      if(!Number.isSafeInteger(expiry)||expiry<=now)return reply(403);
      // D1 supplies atomic nonce uniqueness across Worker isolates.
      const id=hex(await digest(body.device_id+'\0'+body.key+'\0'+body.nonce));
      await env.DB.prepare('DELETE FROM reaper_v85_nonces WHERE expires <= ?').bind(now).run();
      await env.DB.prepare('DELETE FROM reaper_v85_sessions WHERE expires <= ?').bind(now).run();
      const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_v85_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_v85_nonces) < 4096').bind(id,now+120).run();
      if(used.meta?.changes!==1)return reply(403);
      for(let i=0;i<4;i++){const object=await env.REAPER_PAYLOADS.head(`${BUILD}/payload-${i}.bin`);if(!object||object.size!==c.chunks[i].blob_size)return reply(503);}
      const token=crypto.getRandomValues(new Uint8Array(32)),tokenHash=hex(await digest(hex(token)));
      const capsule=await makeCapsule(c,key,body,now,expiry,token);
      await env.DB.prepare('INSERT INTO reaper_v85_sessions (token_hash, expires, build_id) VALUES (?, ?, ?)').bind(tokenHash,Math.min(now+120,expiry),BUILD).run();
      return reply(200,capsule);
    }catch{return reply(503);}
  }
  const match=/^\/v85\/payload\/([0-3])\.bin$/.exec(url.pathname);
  if(!match)return reply(404);if(request.method!=='GET')return reply(405);
  const auth=request.headers.get('Authorization')||'';if(!/^Bearer [0-9a-f]{64}$/.test(auth))return reply(403);
  try{
    if(!env.DB||!env.REAPER_PAYLOADS)return reply(503);
    const session=await env.DB.prepare('SELECT expires, build_id FROM reaper_v85_sessions WHERE token_hash=?').bind(hex(await digest(auth.slice(7)))).first();
    if(!session||session.expires<=Math.floor(Date.now()/1000)||session.build_id!==BUILD)return reply(403);
    const c=validateCatalog(JSON.parse(env.REAPER_CATALOG_JSON));
    const object=await env.REAPER_PAYLOADS.get(`${BUILD}/payload-${match[1]}.bin`);
    if(!object||!object.body||object.size!==c.chunks[Number(match[1])].blob_size)return reply(503);
    return new Response(object.body,{status:200,headers:{...headers,'Content-Length':String(object.size)}});
  }catch{return reply(503);}
}

async function bootstrapHealth(env) {
  const configured = Boolean(env.REAPER_PAYLOADS && env.DB && env.REAPER_SIGNING_KEY_PKCS8 && env.REAPER_CATALOG_JSON);
  const result = { configured, signing_valid: false, payloads_ready: false, database_ready: false };
  if (!configured) return result;
  let c;
  try { ({ c } = await settings(env)); result.signing_valid = true; } catch { return result; }
  try {
    result.payloads_ready = true;
    for (let i = 0; i < 4; i++) {
      const object = await env.REAPER_PAYLOADS.head(`${BUILD}/payload-${i}.bin`);
      if (!object || object.size !== c.chunks[i].blob_size) result.payloads_ready = false;
    }
  } catch { result.payloads_ready = false; }
  try {
    await env.DB.prepare('SELECT identity FROM reaper_v85_nonces LIMIT 1').all();
    await env.DB.prepare('SELECT token_hash FROM reaper_v85_sessions LIMIT 1').all();
    result.database_ready = true;
  } catch {}
  return result;
}

