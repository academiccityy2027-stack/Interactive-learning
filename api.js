const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const random = (n=24) => hex(crypto.getRandomValues(new Uint8Array(n)));
const digest = async s => hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const stamp=()=>new Date().toISOString();
async function hash(p,s=random(16)){const k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);return s+':'+hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:100000,hash:'SHA-256'},k,256))}
function equal(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0}
async function check(p,h){return !!h && equal(await hash(p,h.split(':')[0]),h)}
const fail=(status,message)=>{throw Object.assign(new Error(message),{status})};
const text=(v,n=200)=>typeof v==='string'?v.trim().slice(0,n):'';
const grade=g=>{g=Number(g);if(!Number.isInteger(g)||g<4||g>12)fail(400,'Choose a grade from 4 to 12.');return g};
const pass=p=>{if(typeof p!=='string'||p.length<10||p.length>128)fail(400,'Use a password of 10–128 characters.');return p};
const username=u=>{u=text(u,20).toLowerCase();if(!/^[a-z0-9._-]{3,20}$/.test(u))fail(400,'Username: 3–20 letters, numbers, dots, dashes or underscores.');return u};
const url=v=>{if(!v)return '';try{const u=new URL(v);if(u.protocol!=='https:')throw 0;return u.href.slice(0,2000)}catch{fail(400,'Use a direct HTTPS link.')}};
const avatar=v=>{v=text(v,100000);if(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(v))return v;if([...v].length<=8&&!/[<>]/.test(v))return v||'🚀';fail(400,'Choose a small PNG/JPEG/WebP photo or emoji.');};
const safeUser=u=>({id:u.id,username:u.username,name:u.name,grade:u.grade,avatar:u.avatar,role:u.role});
const cleanContent=c=>{const qs=JSON.parse(c.questions||'[]');return {...c,questions:qs.map(q=>({text:q.text,options:q.options,topic:q.topic})),owner_id:undefined};};
function normalizeQuestions(qs){if(!Array.isArray(qs)||qs.length>30)fail(400,'Provide up to 30 questions.');return qs.map(q=>{if(!text(q.text)||!Array.isArray(q.options)||q.options.length<2||q.options.length>6||!Number.isInteger(q.correct)||q.correct<0||q.correct>=q.options.length)fail(400,'Each question needs text, 2–6 options and a valid correct answer index.');return {text:text(q.text,500),options:q.options.map(o=>text(o,250)),correct:q.correct,topic:text(q.topic,100)||'General',explanation:text(q.explanation,500)}})}
export async function api(req,env,SEEDS){
 const db=env.DB;if(!db)return Response.json({error:'Database binding is not configured.'},{status:503});
 const uurl=new URL(req.url),path=uurl.pathname,method=req.method;
 const one=(sql,...args)=>db.prepare(sql).bind(...args).first();
 const all=async(sql,...args)=>(await db.prepare(sql).bind(...args).all()).results;
 const run=(sql,...args)=>db.prepare(sql).bind(...args).run();
 const reply=(x,status=200,cookie)=>new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store',...(cookie?{'Set-Cookie':cookie}:{})}});
 let body={};
 try{
 if(method!=='GET'){
  if(req.headers.get('Origin')!==uurl.origin||req.headers.get('X-Learning-Universe')!=='1')fail(403,'This request must come from the school application.');
  if(Number(req.headers.get('Content-Length')||0)>250000)fail(413,'Request too large.');
  const raw=await req.text();if(raw.length>250000)fail(413,'Request too large.');try{body=JSON.parse(raw||'{}')}catch{fail(400,'Invalid request.');}
 }
 async function limit(key,max=15,period=900){const now=Math.floor(Date.now()/1000),bucket=Math.floor(now/period);key=await digest(key+':'+bucket);const row=await one('INSERT INTO limits(key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count',key,now+period);if(row.count>max)fail(429,'Too many attempts. Please wait and try again.');}
 const ip=req.headers.get('CF-Connecting-IP')||'local';
 let session=null,user=null;const token=(req.headers.get('Cookie')||'').match(/(?:^|;\s*)lu_session=([a-f0-9]{64})(?:;|$)/)?.[1];
 if(token){session=await one('SELECT * FROM sessions WHERE token=? AND expires>?',await digest(token),Date.now());if(session)user=await one('SELECT * FROM users WHERE id=?',session.user_id);}
 const auth=()=>{if(!user)fail(401,'Sign in to continue.');return user};
 const staff=()=>{auth();if(!['teacher','admin'].includes(user.role))fail(403,'Teacher access required.');};
 const admin=()=>{auth();if(user.role!=='admin')fail(403,'Administrator access required.');};
 async function classAccess(id){staff();const c=await one('SELECT * FROM classes WHERE id=?',id);if(!c)fail(404,'Class not found.');if(user.role!=='admin'&&c.teacher_id!==user.id)fail(403,'This class is not assigned to you.');return c;}
 async function canSee(c){if(c.owner_id==='system')return c.grade===Number(uurl.searchParams.get('grade')||user?.grade||4);if(!user)return false;if(user.role==='admin')return true;if(c.class_id){if(user.role==='teacher')return !!await one('SELECT 1 FROM classes WHERE id=? AND teacher_id=?',c.class_id,user.id);return !!await one('SELECT 1 FROM memberships WHERE class_id=? AND user_id=?',c.class_id,user.id);}return c.owner_id===user.id||user.grade===c.grade;}
 async function contentById(id){const seed=SEEDS.find(c=>c.id===id);const c=seed||await one('SELECT * FROM content WHERE id=?',id);if(!c||!await canSee(c))fail(404,'This content is unavailable for your grade or class.');return c;}
 const cookie=t=>'lu_session='+t+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800';
 async function login(u){const t=random(32);await run('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)',await digest(t),u.id,Date.now()+604800000);return cookie(t)}
 async function audit(action,target){await run('INSERT INTO audit VALUES(?,?,?,?,?)',random(12),user.id,action,target,stamp())}

 // School messages and announcements are stored in preview D1.
 if(path.startsWith('/api/comms/')){
  auth();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_messages (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL, read_at TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS lu_msg_received ON lu_messages(receiver_id,created)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_announcements (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL)").run();
 }
 const allowedContact=async other=>{
  if(other.id===user.id)return false;
  if(user.role==='admin'||other.role==='admin')return true;
  if(user.role==='teacher'&&other.role==='student')return !!await one('SELECT 1 FROM memberships m JOIN classes c ON m.class_id=c.id WHERE m.user_id=? AND c.teacher_id=?',other.id,user.id);
  if(user.role==='student'&&other.role==='teacher')return !!await one('SELECT 1 FROM memberships m JOIN classes c ON m.class_id=c.id WHERE m.user_id=? AND c.teacher_id=?',user.id,other.id);
  return false;
 };
 if(path==='/api/comms/contacts'&&method==='GET'){
  const people=await all('SELECT id,username,name,role,grade FROM users WHERE id<>? ORDER BY name LIMIT 500',user.id),contacts=[];
  for(const other of people)if(await allowedContact(other))contacts.push(other);
  return reply({contacts});
 }
 if(path==='/api/comms/messages'&&method==='GET'){
  const sent=uurl.searchParams.get('mode')==='sent';
  const rows=sent?await all('SELECT m.id,m.subject,m.body,m.created,m.read_at,u.username AS contact_username,u.name AS contact_name FROM lu_messages m JOIN users u ON u.id=m.receiver_id WHERE m.sender_id=? ORDER BY m.created DESC LIMIT 80',user.id):await all('SELECT m.id,m.subject,m.body,m.created,m.read_at,u.username AS contact_username,u.name AS contact_name FROM lu_messages m JOIN users u ON u.id=m.sender_id WHERE m.receiver_id=? ORDER BY m.created DESC LIMIT 80',user.id);
  return reply({messages:rows});
 }
 if(path==='/api/comms/send'&&method==='POST'){
  await limit('school-message:'+user.id,25,3600);
  const other=await one('SELECT id,role FROM users WHERE id=?',text(body.recipient,100));
  if(!other||!await allowedContact(other))fail(403,'This recipient is not an approved school contact.');
  const subject=text(body.subject,100),message=text(body.message,1800);
  if(!subject||message.length<2)fail(400,'Enter a subject and a message.');
  await run('INSERT INTO lu_messages(id,sender_id,receiver_id,subject,body,created) VALUES(?,?,?,?,?,?)',random(12),user.id,other.id,subject,message,stamp());
  return reply({ok:true},201);
 }
 if(path==='/api/comms/read'&&method==='POST'){
  await run('UPDATE lu_messages SET read_at=? WHERE id=? AND receiver_id=? AND read_at IS NULL',stamp(),text(body.id,100),user.id);
  return reply({ok:true});
 }
 if(path==='/api/comms/notifications'&&method==='GET'){
  const unread=await all('SELECT m.id,m.subject,m.created,u.name AS sender FROM lu_messages m JOIN users u ON u.id=m.sender_id WHERE m.receiver_id=? AND m.read_at IS NULL ORDER BY m.created DESC LIMIT 20',user.id);
  const announcements=await all('SELECT id,title,body,created FROM lu_announcements ORDER BY created DESC LIMIT 12');
  return reply({unread:unread.length,messages:unread,announcements});
 }
 if(path==='/api/comms/announce'&&method==='POST'){
  admin();await limit('school-announce:'+user.id,10,3600);
  const title=text(body.title,100),message=text(body.message,1000);
  if(!title||message.length<2)fail(400,'Enter an announcement title and message.');
  await run('INSERT INTO lu_announcements VALUES(?,?,?,?,?)',random(12),user.id,title,message,stamp());
  await audit('announcement',title);
  return reply({ok:true});
 }

 // Class notices and calendar entries are scoped to enrolled students or assigned staff.
 if(path.startsWith('/api/school/')){
  auth();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_class_notices (id TEXT PRIMARY KEY,class_id TEXT NOT NULL,author_id TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,created TEXT NOT NULL)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS lu_class_notices_class_idx ON lu_class_notices(class_id,created)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_calendar_events (id TEXT PRIMARY KEY,class_id TEXT NOT NULL,author_id TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL,due_at TEXT NOT NULL,created TEXT NOT NULL)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS lu_calendar_events_class_idx ON lu_calendar_events(class_id,due_at)").run();
 }
 const visibleClass=async id=>{
  const c=await one('SELECT * FROM classes WHERE id=?',id);if(!c)return null;
  if(user.role==='admin')return c;
  if(user.role==='teacher')return c.teacher_id===user.id?c:null;
  return await one('SELECT 1 FROM memberships WHERE class_id=? AND user_id=?',id,user.id)?c:null;
 };
 if(path==='/api/school/classes'&&method==='GET'){
  const cs=user.role==='admin'&&uurl.searchParams.get('scope')!=='mine'?await all('SELECT * FROM classes ORDER BY grade,name'):user.role==='teacher'||user.role==='admin'?await all('SELECT * FROM classes WHERE teacher_id=? ORDER BY grade,name',user.id):await all('SELECT c.* FROM classes c JOIN memberships m ON c.id=m.class_id WHERE m.user_id=? ORDER BY c.grade,c.name',user.id);
  return reply({classes:cs.map(c=>({id:c.id,name:c.name,grade:c.grade,assigned:c.teacher_id===user.id}))});
 }
 if(path==='/api/school/feed'&&method==='GET'){
  const cs=user.role==='admin'&&uurl.searchParams.get('scope')!=='mine'?await all('SELECT id,name,grade FROM classes'):user.role==='teacher'||user.role==='admin'?await all('SELECT id,name,grade FROM classes WHERE teacher_id=?',user.id):await all('SELECT c.id,c.name,c.grade FROM classes c JOIN memberships m ON m.class_id=c.id WHERE m.user_id=?',user.id);
  const ids=cs.map(c=>c.id);if(!ids.length)return reply({notices:[],events:[]});
  const filter='('+ids.map(()=>'?').join(',')+')';
  const notices=await all('SELECT id,class_id,title,message,created FROM lu_class_notices WHERE class_id IN '+filter+' ORDER BY created DESC LIMIT 80',...ids);
  const events=await all('SELECT id,class_id,title,details,due_at,created FROM lu_calendar_events WHERE class_id IN '+filter+' ORDER BY due_at ASC LIMIT 150',...ids);
  const byId=Object.fromEntries(cs.map(c=>[c.id,c]));
  return reply({notices:notices.map(n=>({...n,className:byId[n.class_id]?.name||'Class'})),events:events.map(e=>({...e,className:byId[e.class_id]?.name||'Class'}))});
 }
 if(path==='/api/school/notices/new'&&method==='POST'){
  staff();const classId=text(body.classId,100),c=await visibleClass(classId);
  if(!c)fail(403,'You are not assigned to this class.');
  const title=text(body.title,100),message=text(body.message,1200);
  if(!title||!message)fail(400,'Enter an announcement title and message.');
  await limit('class-notice:'+user.id,25,3600);
  await run('INSERT INTO lu_class_notices VALUES(?,?,?,?,?,?)',random(12),classId,user.id,title,message,stamp());
  await audit('class_notice',classId);return reply({ok:true},201);
 }
 if(path==='/api/school/events/new'&&method==='POST'){
  staff();const classId=text(body.classId,100),c=await visibleClass(classId);
  if(!c)fail(403,'You are not assigned to this class.');
  const title=text(body.title,100),details=text(body.details,900),raw=text(body.dueAt,40),date=new Date(raw);
  if(!title||!raw||!Number.isFinite(date.getTime())||date.getTime()<Date.now()-86400000||date.getTime()>Date.now()+63072000000)fail(400,'Enter a valid title and upcoming due date.');
  await limit('class-event:'+user.id,30,3600);
  await run('INSERT INTO lu_calendar_events VALUES(?,?,?,?,?,?,?)',random(12),classId,user.id,title,details,date.toISOString(),stamp());
  await audit('calendar_event',classId);return reply({ok:true},201);
 }
 if(path==='/api/me'&&method==='GET')return reply({user:user?safeUser(user):null});
 if(['/api/register','/api/login','/api/recover'].includes(path)&&method==='POST'){
  await limit('auth-ip:'+ip,40);await limit('auth-name:'+text(body.username).toLowerCase(),12);
  if(path==='/api/register'){
   const n=username(body.username),p=pass(body.password),g=grade(body.grade),id=random(16),code=random(16);
   if(await one('SELECT 1 FROM users WHERE username=?',n))fail(409,'Username is already taken.');
   const h=await hash(p);await run('INSERT INTO users(id,username,name,grade,avatar,password,recovery,created) VALUES(?,?,?,?,?,?,?,?)',id,n,text(body.name,50)||n,g,avatar(body.avatar||'🚀'),h,await digest(code),stamp());
   const u=await one('SELECT * FROM users WHERE id=?',id);return reply({user:safeUser(u),recoveryCode:code},201,await login(u));
  }
  const u=await one('SELECT * FROM users WHERE username=?',text(body.username,20).toLowerCase());
  if(path==='/api/login'){
   const portal=body.portal==='teacher'?'teacher':'student';
   const number=text(body.employeeNumber,20);
   const correctRole=portal==='teacher'?(u?.role==='teacher'&&/^[0-9]{1,20}$/.test(number)&&u.employee_number===number):(u?.role==='student'||u?.role==='admin');
   const ok=u?await check(typeof body.password==='string'?body.password:'',u.password):await check('dummy','00000000000000000000000000000000:'+('0'.repeat(64)));
   if(!u||!ok||!correctRole)fail(401,'Login details are incorrect or this account is not approved for this portal.');
   return reply({user:safeUser(u)},200,await login(u));
  }
  pass(body.password);if(!u||!equal(await digest(text(body.code,80)),u.recovery))fail(400,'Username or recovery code is incorrect.');
  const code=random(16);await db.batch([db.prepare('UPDATE users SET password=?,recovery=? WHERE id=?').bind(await hash(body.password),await digest(code),u.id),db.prepare('DELETE FROM sessions WHERE user_id=?').bind(u.id)]);return reply({recoveryCode:code,message:'Password reset. Save your new recovery code and sign in.'});
 }
 if(path==='/api/logout'&&method==='POST'){if(session)await run('DELETE FROM sessions WHERE token=?',session.token);return reply({ok:true},200,'lu_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');}
 if(path==='/api/profile'&&method==='POST'){auth();await run('UPDATE users SET name=?,grade=?,avatar=? WHERE id=?',text(body.name,50)||user.name,grade(body.grade),avatar(body.avatar||user.avatar),user.id);return reply({user:safeUser(await one('SELECT * FROM users WHERE id=?',user.id))});}
 if(path==='/api/password'&&method==='POST'){auth();await limit('password:'+user.id,10);if(!await check(typeof body.current==='string'?body.current:'',user.password))fail(400,'Current password is incorrect.');const code=random(16);await db.batch([db.prepare('UPDATE users SET password=?,recovery=? WHERE id=?').bind(await hash(pass(body.password)),await digest(code),user.id),db.prepare('DELETE FROM sessions WHERE user_id=?').bind(user.id)]);return reply({recoveryCode:code,message:'Password changed. Save this recovery code.'},200,await login(user));}
 if(path==='/api/admin/activate'&&method==='POST'){auth();await limit('activate:'+ip,5);if(!env.ADMIN_SETUP_CODE||!equal(text(body.code,100),env.ADMIN_SETUP_CODE))fail(403,'Invalid administrator activation code.');const r=await one("UPDATE users SET role='admin' WHERE id=? AND NOT EXISTS(SELECT 1 FROM users WHERE role='admin') RETURNING id",user.id);if(!r)fail(409,'An administrator is already configured.');await audit('admin_activation',user.id);return reply({user:safeUser(await one('SELECT * FROM users WHERE id=?',user.id))});}

 // Administration analytics are based on real assessed work, never sign-in counts.
 if(path.startsWith('/api/admin/center/')){
  admin();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_support_tickets(id TEXT PRIMARY KEY,author_id TEXT NOT NULL,subject TEXT NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created TEXT NOT NULL,updated TEXT NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_recognition(id TEXT PRIMARY KEY,student_id TEXT NOT NULL,awarded_by TEXT NOT NULL,title TEXT NOT NULL,note TEXT NOT NULL,created TEXT NOT NULL)").run();
 }
 if(path==='/api/admin/center/overview'&&method==='GET'){
  const date=t=>{const v=uurl.searchParams.get(t);if(!v)return t==='start'?'1970-01-01':'9999-12-31';if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(v))fail(400,'Invalid date.');return v};
  const start=date('start'),end=date('end');if(start>end)fail(400,'Start date must be before end date.');
  const stats=await one("SELECT (SELECT COUNT(*) FROM users) users,(SELECT COUNT(*) FROM users WHERE role='teacher') teachers,(SELECT COUNT(*) FROM users WHERE role='student') students,(SELECT COUNT(*) FROM classes) classes,(SELECT COUNT(*) FROM results WHERE substr(created,1,10)>=? AND substr(created,1,10)<=?) submissions,(SELECT COUNT(DISTINCT user_id) FROM results WHERE substr(created,1,10)>=? AND substr(created,1,10)<=?) active_learners,(SELECT COUNT(*) FROM lu_support_tickets WHERE status<>'resolved') open_tickets",start,end,start,end);
  const classes=await all('SELECT c.id,c.name,c.grade,u.name teacher,(SELECT COUNT(*) FROM memberships m WHERE m.class_id=c.id) students FROM classes c LEFT JOIN users u ON u.id=c.teacher_id ORDER BY c.grade,c.name LIMIT 500');
  const teachers=await all("SELECT u.id,u.name,u.username,COUNT(DISTINCT c.id) classes,COUNT(DISTINCT ct.id) published_resources,COUNT(DISTINCT r.id) student_attempts FROM users u LEFT JOIN classes c ON c.teacher_id=u.id LEFT JOIN content ct ON ct.owner_id=u.id LEFT JOIN results r ON r.class_id=c.id AND substr(r.created,1,10)>=? AND substr(r.created,1,10)<=? WHERE u.role IN ('teacher','admin') GROUP BY u.id ORDER BY published_resources DESC,student_attempts DESC,u.name LIMIT 200",start,end);
  const resultRows=await all("SELECT r.user_id,r.content_id,r.class_id,r.grade,r.score,r.total,r.created,u.name student FROM results r JOIN users u ON u.id=r.user_id WHERE substr(r.created,1,10)>=? AND substr(r.created,1,10)<=? ORDER BY r.created DESC LIMIT 7000",start,end);
  const best=new Map();for(const r of resultRows){if(r.total<=0)continue;const key=r.user_id+':'+r.content_id;const previous=best.get(key);if(!previous||r.score/r.total>previous.score/previous.total)best.set(key,r)}
  const classAgg=new Map(classes.map(c=>[c.id,{id:c.id,name:c.name,grade:c.grade,teacher:c.teacher,students:c.students,completed:0,assessed:0,points:0}]));
  for(const r of best.values()){if(!r.class_id||!classAgg.has(r.class_id))continue;const x=classAgg.get(r.class_id);x.assessed++;x.points+=r.score/r.total*100;if(r.score/r.total>=.6)x.completed++}
  const rankings=[...classAgg.values()].filter(c=>c.assessed>0).map(c=>({...c,average:Math.round(c.points/c.assessed)})).sort((a,b)=>b.completed-a.completed||b.average-a.average);
  const ticketRows=await all("SELECT t.id,t.subject,t.details,t.status,t.created,t.updated,u.name,u.username FROM lu_support_tickets t LEFT JOIN users u ON u.id=t.author_id ORDER BY t.updated DESC LIMIT 100");
  const awards=await all("SELECT r.id,r.title,r.note,r.created,u.name student FROM lu_recognition r JOIN users u ON u.id=r.student_id ORDER BY r.created DESC LIMIT 100");
  return reply({stats,classes,teachers,rankings,tickets:ticketRows,awards,truncated:resultRows.length===7000,dateRange:{start,end}});
 }
 if(path==='/api/admin/center/report'&&method==='GET'){
  const start=uurl.searchParams.get('start')||'1970-01-01',end=uurl.searchParams.get('end')||'9999-12-31',cid=uurl.searchParams.get('class')||'';
  if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(start)||!/^\\d{4}-\\d{2}-\\d{2}$/.test(end)||start>end)fail(400,'Invalid report dates.');
  const allRows=await all("SELECT u.name student,u.username,r.grade,c.name classroom,t.name teacher,r.subject,r.title,r.score,r.total,r.created FROM results r JOIN users u ON u.id=r.user_id LEFT JOIN classes c ON c.id=r.class_id LEFT JOIN users t ON t.id=c.teacher_id WHERE substr(r.created,1,10)>=? AND substr(r.created,1,10)<=? AND (?='' OR r.class_id=?) ORDER BY r.created DESC LIMIT 10000",start,end,cid,cid);
  const rows=[['Student','Username','Grade','Class','Teacher','Subject','Assessment','Score','Total','Percentage','Submitted (UTC)'],...allRows.filter(r=>r.total>0).map(r=>[r.student,r.username,r.grade,r.classroom||'',r.teacher||'',r.subject,r.title,r.score,r.total,Math.round(r.score/r.total*100),r.created])];
  const format=uurl.searchParams.get('format');if(format==='xlsx')return new Response(makeXlsx(rows),{headers:{'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="learning-universe-school-report.xlsx"','Cache-Control':'no-store'}});
  if(format==='csv'){const csv=rows.map(row=>row.map(v=>'"'+String(v??'').replaceAll('"','""').replace(/^[=+\\-@]/,'\u0027 if(path==='/api/admin/users'&&method==='GET')')+'"').join(',')).join('\\r\\n');return new Response(csv,{headers:{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="learning-universe-school-report.csv"','Cache-Control':'no-store'}})}
  return reply({rows:rows.slice(0,501),total:rows.length-1,truncated:allRows.length===10000});
 }
 if(path==='/api/admin/center/ticket-status'&&method==='POST'){
  const id=text(body.id,100),status=text(body.status,20);
  if(!['open','in_progress','resolved'].includes(status))fail(400,'Invalid ticket status.');
  const found=await one('SELECT id FROM lu_support_tickets WHERE id=?',id);if(!found)fail(404,'Ticket not found.');
  await run('UPDATE lu_support_tickets SET status=?,updated=? WHERE id=?',status,stamp(),id);await audit('ticket_'+status,id);return reply({ok:true});
 }
 if(path==='/api/admin/center/award'&&method==='POST'){
  const target=await one("SELECT id FROM users WHERE id=? AND role='student'",text(body.studentId,100));
  const title=text(body.title,90),note=text(body.note,400);
  if(!target||!title)fail(400,'Choose a student and recognition title.');
  await run('INSERT INTO lu_recognition VALUES(?,?,?,?,?,?)',random(12),target.id,user.id,title,note,stamp());await audit('recognition',target.id);return reply({ok:true});
 }
 if(path==='/api/support/tickets'&&method==='POST'){
  auth();await limit('support-tickets:'+user.id,8,3600);
  await db.prepare("CREATE TABLE IF NOT EXISTS lu_support_tickets(id TEXT PRIMARY KEY,author_id TEXT NOT NULL,subject TEXT NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created TEXT NOT NULL,updated TEXT NOT NULL)").run();
  const subject=text(body.subject,100),details=text(body.details,1800);
  if(!subject||details.length<5)fail(400,'Enter a subject and describe the issue.');
  await run('INSERT INTO lu_support_tickets VALUES(?,?,?,?,?,?,?)',random(12),user.id,subject,details,'open',stamp(),stamp());
  return reply({ok:true},201);
 }
 if(path==='/api/support/tickets'&&method==='GET'){
  auth();await db.prepare("CREATE TABLE IF NOT EXISTS lu_support_tickets(id TEXT PRIMARY KEY,author_id TEXT NOT NULL,subject TEXT NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created TEXT NOT NULL,updated TEXT NOT NULL)").run();
  return reply({tickets:await all('SELECT id,subject,details,status,created,updated FROM lu_support_tickets WHERE author_id=? ORDER BY created DESC LIMIT 80',user.id)});
 }
 if(path==='/api/admin/users'&&method==='GET'){admin();return reply({users:(await all('SELECT * FROM users ORDER BY username LIMIT 500')).map(u=>({...safeUser(u),employeeNumber:u.employee_number||null,created:u.created||null}))});}
 if(path==='/api/admin/employee'&&method==='POST'){
  admin();const employee=text(body.employeeNumber,20),id=text(body.id,100);
  if(!/^[0-9]{1,20}$/.test(employee))fail(400,'Employee number must contain 1–20 digits.');
  const target=await one('SELECT * FROM users WHERE id=?',id);
  if(!target||target.role==='admin')fail(400,'Account unavailable.');
  if(await one('SELECT id FROM users WHERE employee_number=? AND id<>?',employee,id))fail(409,'Employee number already assigned.');
  await run('UPDATE users SET employee_number=? WHERE id=?',employee,id);
  await audit('set_verified_employee_number',id);
  return reply({ok:true});
 }
 if(path==='/api/admin/role'&&method==='POST'){admin();if(!['student','teacher'].includes(body.role))fail(400,'Select student or teacher.');if(body.id===user.id)fail(400,'Cannot change your own administrator role.');const target=await one('SELECT * FROM users WHERE id=?',body.id);if(!target||target.role==='admin')fail(400,'User unavailable.');if(body.role==='teacher'&&!target.employee_number)fail(400,'Assign a verified employee number before granting teacher access.');await run('UPDATE users SET role=? WHERE id=?',body.role,body.id);await audit('grant_role:'+body.role,body.id);return reply({ok:true});}
 if(path==='/api/admin/assign'&&method==='POST'){admin();const t=await one("SELECT * FROM users WHERE id=? AND role IN ('teacher','admin')",body.teacherId);if(!t)fail(400,'Choose an approved teacher.');await classAccess(body.classId);await run('UPDATE classes SET teacher_id=? WHERE id=?',body.teacherId,body.classId);await audit('assign_class',body.classId);return reply({ok:true});}
 if(path==='/api/admin/reset-password'&&method==='POST'){
  admin();await limit('admin-reset:'+user.id,10,3600);
  const target=await one('SELECT id,username,role FROM users WHERE id=?',text(body.id,100));
  if(!target||target.role==='admin')fail(403,'Administrators cannot reset another administrator account here.');
  const fresh=pass(body.password),code=random(16);
  await db.batch([db.prepare('UPDATE users SET password=?,recovery=? WHERE id=?').bind(await hash(fresh),await digest(code),target.id),db.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id)]);
  await audit('admin_password_reset',target.id);
  return reply({recoveryCode:code,message:'Password reset. All existing sessions were signed out.'});
 }
 if(path==='/api/reset-student'&&method==='POST'){staff();await limit('reset:'+user.id,20);const target=await one("SELECT * FROM users WHERE id=? AND role='student'",body.id);if(!target)fail(404,'Student unavailable.');if(user.role!=='admin'&&!await one('SELECT 1 FROM memberships m JOIN classes c ON c.id=m.class_id WHERE m.user_id=? AND c.teacher_id=?',target.id,user.id))fail(403,'Student is not in your assigned classes.');const code=random(16);await db.batch([db.prepare('UPDATE users SET password=?,recovery=? WHERE id=?').bind(await hash(pass(body.password)),await digest(code),target.id),db.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id)]);await audit('password_reset',target.id);return reply({recoveryCode:code});}
 if(path==='/api/classes'&&method==='GET'){auth();const cs=user.role==='admin'&&uurl.searchParams.get('scope')!=='mine'?await all('SELECT * FROM classes ORDER BY name'):user.role==='teacher'||user.role==='admin'?await all('SELECT * FROM classes WHERE teacher_id=? ORDER BY name',user.id):await all('SELECT c.* FROM classes c JOIN memberships m ON m.class_id=c.id WHERE m.user_id=? ORDER BY c.name',user.id);return reply({classes:cs});}
 if(path==='/api/classes'&&method==='POST'){staff();const name=text(body.name,80);if(!name)fail(400,'Enter a class name.');const c={id:random(12),name,grade:grade(body.grade),teacher_id:user.id,code:random(5).toUpperCase()};await run('INSERT INTO classes VALUES(?,?,?,?,?)',...Object.values(c));return reply({class:c},201);}
 if(path==='/api/join'&&method==='POST'){auth();if(user.role!=='student')fail(403,'Student accounts join classes.');await limit('join:'+user.id,20);const c=await one('SELECT * FROM classes WHERE code=?',text(body.code,20).toUpperCase());if(!c)fail(404,'Join code not found.');if(c.grade!==user.grade)fail(400,'Your profile grade must match this class.');await run('INSERT OR IGNORE INTO memberships VALUES(?,?)',c.id,user.id);return reply({ok:true});}
 if(path==='/api/content'&&method==='GET'){
 const g=grade(uurl.searchParams.get('grade')||user?.grade||4),subject=uurl.searchParams.get('subject'),cid=uurl.searchParams.get('class');let cs=SEEDS.filter(c=>c.grade===g);
 if(user){const own=await all('SELECT * FROM content WHERE grade=? ORDER BY deadline,title',g);for(const c of own){if(await canSee(c))cs.push(c)}}
 if(subject&&subject!=='all')cs=cs.filter(c=>c.subject===subject);if(cid)cs=cs.filter(c=>c.class_id===cid||c.owner_id==='system');
 const rs=user?await all('SELECT * FROM results WHERE user_id=? ORDER BY created',user.id):[];
 const recent=rs.filter(r=>r.grade===g&&(!subject||subject==='all'||r.subject===subject)).slice(-8);const mastery=recent.length?recent.reduce((n,r)=>n+r.score/r.total,0)/recent.length:null;
 const level=mastery===null?'core':mastery<.6?'foundation':mastery>=.85?'stretch':'core';
 return reply({content:cs.map(c=>({...cleanContent(c),recommended:c.difficulty===level,editable:c.owner_id!=='system'&&!!user&&(user.role==='admin'||c.owner_id===user.id||user.role==='teacher'&&!!c.class_id)})),level,reason:mastery===null?'Start with core activities; recommendations improve after assessed answers.':level==='foundation'?'Practice the foundations before the next challenge.':level==='stretch'?'Strong recent scores: try a stretch challenge.':'Build confidence with core practice.'});
 }
 if(path==='/api/content'&&method==='POST'){
 staff();const id=body.id||random(12);if(body.id){const old=await one('SELECT * FROM content WHERE id=?',id);if(!old)fail(404,'Content not found.');if(old.class_id)await classAccess(old.class_id);if(!old.class_id&&user.role!=='admin'&&old.owner_id!==user.id)fail(403,'Only the author can edit this grade-wide content.');}
 const g=grade(body.grade);let cid=body.classId||null;if(cid){const c=await classAccess(cid);if(c.grade!==g)fail(400,'Class and content grade must match.');}
 if(!['resource','quiz','video','mission'].includes(body.kind))fail(400,'Select a content type.');if(!SUBJECTS.includes(body.subject))fail(400,'Select a subject.');if(!['foundation','core','stretch'].includes(body.difficulty))fail(400,'Select a difficulty.');
 const qs=normalizeQuestions(body.questions||[]);if(['quiz','video','mission'].includes(body.kind)&&!qs.length)fail(400,'Add at least one assessed question.');const title=text(body.title,150);if(!title)fail(400,'Enter a title.');if(body.kind==='video'&&!body.url)fail(400,'Add a specific video URL.');const link=url(body.url);if(body.kind==='video'&&/(results\?|search_query|\/search[/?])/.test(link))fail(400,'Use a specific video, not a search page.');
 let deadline=body.deadline?new Date(body.deadline):null;if(deadline&&isNaN(deadline))fail(400,'Invalid deadline.');
 await run('INSERT INTO content VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET class_id=excluded.class_id,grade=excluded.grade,subject=excluded.subject,kind=excluded.kind,title=excluded.title,description=excluded.description,url=excluded.url,difficulty=excluded.difficulty,deadline=excluded.deadline,questions=excluded.questions',id,user.id,cid,g,body.subject,body.kind,title,text(body.description,2000),link,body.difficulty,deadline?deadline.toISOString():null,JSON.stringify(qs));return reply({ok:true,id});
 }
 if(path==='/api/content/edit'&&method==='GET'){staff();const c=await one('SELECT * FROM content WHERE id=?',uurl.searchParams.get('id'));if(!c||!c.class_id&&user.role!=='admin'&&c.owner_id!==user.id)fail(403,'Author access required.');if(c.class_id)await classAccess(c.class_id);return reply({content:{...c,questions:JSON.parse(c.questions)}});}
 if(path==='/api/submit'&&method==='POST'){
 auth();await limit('submit:'+user.id,60,3600);const c=await contentById(body.id);const qs=JSON.parse(c.questions);if(!qs.length)fail(400,'This resource has no assessment.');if(!Array.isArray(body.answers)||body.answers.length!==qs.length||body.answers.some((a,i)=>!Number.isInteger(a)||a<0||a>=qs[i].options.length))fail(400,'Answer every question.');
 let score=0;const feedback=qs.map((q,i)=>{const correct=body.answers[i]===q.correct;if(correct)score++;return {text:q.text,topic:q.topic,correct,selected:q.options[body.answers[i]],answer:q.options[q.correct],explanation:q.explanation||''}});
 const r={id:random(12),user_id:user.id,content_id:c.id,title:c.title,subject:c.subject,grade:c.grade,class_id:c.class_id||null,score,total:qs.length,answers:JSON.stringify(body.answers),feedback:JSON.stringify(feedback),created:stamp()};await run('INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',...Object.values(r));return reply({result:{...r,feedback,answers:body.answers},message:'Result saved. XP rewards your best assessed score; repeated attempts do not duplicate points.'});
 }
 async function resultsForClass(cid){const c=await classAccess(cid);return all('SELECT r.*,u.name,u.username FROM results r JOIN users u ON u.id=r.user_id WHERE r.class_id=? OR (r.class_id IS NULL AND r.grade=? AND r.user_id IN (SELECT user_id FROM memberships WHERE class_id=?)) ORDER BY r.created DESC',cid,c.grade,cid)}
 if(path==='/api/results'&&method==='GET'){auth();const rs=await all('SELECT r.*, c.kind FROM results r LEFT JOIN content c ON c.id=r.content_id WHERE r.user_id=? ORDER BY r.created DESC LIMIT 500',user.id);const best={};rs.forEach(r=>{if(!best[r.content_id]||r.score/r.total>best[r.content_id].score/best[r.content_id].total)best[r.content_id]=r});const xp=Object.values(best).reduce((s,r)=>s+r.score*10+(r.score===r.total?20:0),0);const sc={};Object.values(best).forEach(r=>sc[r.subject]=Math.max(sc[r.subject]||0,Math.round(r.score/r.total*3)));const completed=Object.values(best).filter(r=>r.score/r.total>=.6).length;let streak=0,bestStreak=0;[...rs].reverse().forEach(r=>JSON.parse(r.feedback).forEach(f=>{streak=f.correct?streak+1:0;bestStreak=Math.max(bestStreak,streak)}));return reply({results:rs.map(r=>({...r,feedback:JSON.parse(r.feedback),answers:JSON.parse(r.answers)})),progress:{xp,sc,best:bestStreak,streak},completed,badges:[...(rs.length?['First Launch']:[]),...(Object.values(best).some(r=>r.score===r.total)?['Perfect Score']:[]),...(completed>=5?['Mission Pilot']:[])]});}
 if(path==='/api/leaderboard'&&method==='GET'){
 auth();const cid=uurl.searchParams.get('class');const c=await one('SELECT * FROM classes WHERE id=?',cid);if(!c)fail(404,'Class not found.');if(user.role!=='admin'&&c.teacher_id!==user.id&&!await one('SELECT 1 FROM memberships WHERE class_id=? AND user_id=?',cid,user.id))fail(403,'Class member access required.');
 const members=await all('SELECT u.id,u.name FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.class_id=?',cid);
 const rs=await all('SELECT * FROM results WHERE class_id=? OR (class_id IS NULL AND grade=? AND user_id IN (SELECT user_id FROM memberships WHERE class_id=?))',cid,c.grade,cid);
 const summaries=members.map(m=>{const best={};rs.filter(r=>r.user_id===m.id).forEach(r=>{if(!best[r.content_id]||r.score/r.total>best[r.content_id].score/best[r.content_id].total)best[r.content_id]=r});const vals=Object.values(best);return {name:m.name,completed:vals.filter(r=>r.score/r.total>=.6).length,assessed:vals.length,performance:vals.length?Math.round(vals.reduce((n,r)=>n+r.score/r.total,0)/vals.length*100):0}});
 const active=summaries.sort((a,b)=>b.completed-a.completed)[0];const high=summaries.filter(m=>m.assessed>=3).sort((a,b)=>b.performance-a.performance)[0];return reply({mostActive:active?.completed?{name:active.name,completed:active.completed}:null,highestPerformance:high?{name:high.name,score:high.performance}:null});
 }
 if(path==='/api/dashboard'&&method==='GET'){
 const cid=uurl.searchParams.get('class');await classAccess(cid);const subject=uurl.searchParams.get('subject');const members=(await all('SELECT u.* FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.class_id=?',cid)).map(safeUser);let rs=await resultsForClass(cid);if(subject&&subject!=='all')rs=rs.filter(r=>r.subject===subject);const missions=await all('SELECT * FROM content WHERE class_id=?',cid);const summary=members.map(m=>{const mine=rs.filter(r=>r.user_id===m.id),best={};mine.forEach(r=>{if(!best[r.content_id]||r.score/r.total>best[r.content_id].score/best[r.content_id].total)best[r.content_id]=r});const vals=Object.values(best);const practice=[...new Set(mine.slice(0,10).flatMap(r=>JSON.parse(r.feedback).filter(f=>!f.correct).map(f=>f.topic)))];return {...m,completed:vals.filter(r=>r.score/r.total>=.6).length,assessed:vals.length,performance:vals.length?Math.round(vals.reduce((n,r)=>n+r.score/r.total,0)/vals.length*100):null,practice,missions:missions.filter(c=>!subject||subject==='all'||c.subject===subject).map(c=>({id:c.id,title:c.title,deadline:c.deadline,status:best[c.id]?best[c.id].score/best[c.id].total>=.6?'Completed':'Needs practice':c.deadline&&new Date(c.deadline)<new Date()?'Overdue':'Assigned',score:best[c.id]?Math.round(best[c.id].score/best[c.id].total*100):null}))}});
 const active=[...summary].sort((a,b)=>b.completed-a.completed)[0],performer=[...summary].filter(m=>m.assessed>=3).sort((a,b)=>b.performance-a.performance)[0];return reply({members:summary,results:rs.map(r=>({...r,feedback:JSON.parse(r.feedback)})),missions:missions.map(cleanContent),mostActive:active?.completed?{name:active.name,completed:active.completed}:null,highestPerformance:performer?{name:performer.name,score:performer.performance}:null});
 }
 if(path==='/api/report'&&method==='GET'){
 const cid=uurl.searchParams.get('class');let rs=await resultsForClass(cid);const sj=uurl.searchParams.get('subject');if(sj&&sj!=='all')rs=rs.filter(r=>r.subject===sj);const rows=[['Student','Username','Grade','Subject','Task','Score','Total','Percentage','Date','Topics to practise'],...rs.map(r=>[r.name,r.username,r.grade,r.subject,r.title,r.score,r.total,Math.round(r.score/r.total*100),r.created,JSON.parse(r.feedback).filter(f=>!f.correct).map(f=>f.topic).join('; ')])];
 if(uurl.searchParams.get('format')==='xlsx'){return new Response(makeXlsx(rows),{headers:{'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="Learning_Universe_Report.xlsx"','Cache-Control':'no-store'}})}
 const cell=v=>'"'+String(v??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';return new Response('\ufeff'+rows.map(row=>row.map(cell).join(',')).join('\r\n'),{headers:{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="Learning_Universe_Report.csv"','Cache-Control':'no-store'}});
 }
 if(path==='/api/projects'&&method==='GET'){auth();const cs=await all('SELECT * FROM projects ORDER BY created DESC LIMIT 300');const ps=[];for(const p of cs){const c=await one('SELECT * FROM classes WHERE id=?',p.class_id);const member=await one('SELECT 1 FROM memberships WHERE class_id=? AND user_id=?',p.class_id,user.id);if(user.role==='admin'||c?.teacher_id===user.id||p.user_id===user.id||member&&p.approved){const author=await one('SELECT name,grade FROM users WHERE id=?',p.user_id);ps.push({...p,name:author.name,grade:author.grade})}}return reply({projects:ps});}
 if(path==='/api/projects'&&method==='POST'){auth();const c=await one('SELECT * FROM classes WHERE id=?',body.classId);if(!c)fail(400,'Choose a class.');if(user.role==='student'&&!await one('SELECT 1 FROM memberships WHERE class_id=? AND user_id=?',c.id,user.id))fail(403,'Join this class first.');if(user.role!=='student')await classAccess(c.id);if(!['Arduino','Robotics','Coding','Design'].includes(body.category))fail(400,'Select a project category.');const title=text(body.title,150),description=text(body.description,2000);if(!title||!description)fail(400,'Add a title and description.');const image=body.image?avatar(body.image):'';if(image&&!image.startsWith('data:image/'))fail(400,'Upload an image.');await run('INSERT INTO projects VALUES(?,?,?,?,?,?,?,?,?,?)',random(12),user.id,c.id,title,body.category,description,url(body.url),image,user.role==='student'?0:1,stamp());return reply({ok:true});}
 if(path==='/api/projects/approve'&&method==='POST'){staff();const p=await one('SELECT * FROM projects WHERE id=?',body.id);if(!p)fail(404,'Project not found.');await classAccess(p.class_id);await run('UPDATE projects SET approved=? WHERE id=?',body.approved?1:0,p.id);await audit('project_review',p.id);return reply({ok:true});}
 fail(404,'Endpoint not found.');
 }catch(e){return reply({error:e.status?e.message:'The server could not complete this request. Please try again.'},e.status||500)}
}
const SUBJECTS=['math','english','science','physics','biology','chemistry','national','ict','art','pe'];
// Minimal standards-compliant OOXML workbook; text uses inline strings to prevent formula injection.
function makeXlsx(rows){
 const esc=v=>String(v??'').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
 const sheet='<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" state="frozen"/></sheetView></sheetViews><cols><col min="1" max="10" width="24" customWidth="1"/></cols><sheetData>'+rows.map((r,i)=>'<row r="'+(i+1)+'">'+r.map(v=>typeof v==='number'?'<c><v>'+v+'</v></c>':'<c t="inlineStr"><is><t xml:space="preserve">'+esc(v)+'</t></is></c>').join('')+'</row>').join('')+'</sheetData><autoFilter ref="A1:J'+rows.length+'"/></worksheet>';
 const files={
 '[Content_Types].xml':'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
 '_rels/.rels':'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
 'xl/workbook.xml':'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Class report" sheetId="1" r:id="rId1"/></sheets></workbook>',
 'xl/_rels/workbook.xml.rels':'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
 'xl/worksheets/sheet1.xml':sheet};
 const chunks=[],central=[];let offset=0,size=0;const crc=b=>{let c=0xffffffff;for(const x of b){c^=x;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0)}return(c^0xffffffff)>>>0};
 for(const [name,str]of Object.entries(files)){const n=enc.encode(name),b=enc.encode(str),sum=crc(b),h=new Uint8Array(30+n.length),v=new DataView(h.buffer);v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);v.setUint32(14,sum,true);v.setUint32(18,b.length,true);v.setUint32(22,b.length,true);v.setUint16(26,n.length,true);h.set(n,30);chunks.push(h,b);const c=new Uint8Array(46+n.length),w=new DataView(c.buffer);w.setUint32(0,0x02014b50,true);w.setUint16(4,20,true);w.setUint16(6,20,true);w.setUint32(16,sum,true);w.setUint32(20,b.length,true);w.setUint32(24,b.length,true);w.setUint16(28,n.length,true);w.setUint32(42,offset,true);c.set(n,46);central.push(c);size+=c.length;offset+=h.length+b.length;}
 const end=new Uint8Array(22),v=new DataView(end.buffer);v.setUint32(0,0x06054b50,true);v.setUint16(8,central.length,true);v.setUint16(10,central.length,true);v.setUint32(12,size,true);v.setUint32(16,offset,true);const out=new Uint8Array(offset+size+22);let pos=0;for(const b of [...chunks,...central,end]){out.set(b,pos);pos+=b.length}return out;
}
