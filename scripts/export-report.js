const fs   = require("fs");
const path = require("path");
const { generateMarkdown } = require("../server");

const dataFile = path.join(__dirname, "..", "data", "events.json");
const outDir   = path.join(__dirname, "..", "exports");
const outFile  = path.join(outDir, "honeypot-report.md");

if (!fs.existsSync(dataFile)) { console.error("No events.json found."); process.exit(1); }

const events = JSON.parse(fs.readFileSync(dataFile, "utf8"));
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, generateMarkdown(events) + "\n");
console.log(`✓ Report exported to ${outFile}`);
