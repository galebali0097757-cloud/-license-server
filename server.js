// r93 server initialization: encrypted at rest and session-bound after licensing.
// v88 deployment stamp: 2026-10-06 secure-session-v2
const {handleV86,operationalHealth,v88Operational,v88Lease,r93Lease,r93Health,R93_ENGINE_SEAL,r94Lease,r94Health,R94_ENGINE_SEAL}=(()=>{
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

return {handleV86,operationalHealth,v88Operational,v88Lease,r93Lease,r93Health,R93_ENGINE_SEAL,r94Lease,r94Health,R94_ENGINE_SEAL};
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
        menu_initialization: await r94Health(env)
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
        if (body?.protocol === "r88" || body?.protocol === "r93" || body?.protocol === "r94") {
          const licenseExpiry = Math.floor(Date.parse(row.expires_at) / 1000);
          try {
            secure = await (body.protocol === "r94" ? r94Lease : body.protocol === "r93" ? r93Lease : v88Lease)(env, {
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

