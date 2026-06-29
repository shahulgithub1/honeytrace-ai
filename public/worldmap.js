const WorldMap = (() => {
  let geoData = null;
  let clickCB = null;

  const NAME_MAP = {
    "Russia":"Russia","Russian Federation":"Russia","China":"China",
    "Netherlands":"Netherlands","Vietnam":"Vietnam","Viet Nam":"Vietnam",
    "Germany":"Germany","United States of America":"United States","United States":"United States",
    "Brazil":"Brazil","India":"India","Ukraine":"Ukraine","Romania":"Romania",
    "Iran":"Iran","Iran (Islamic Republic of)":"Iran","Turkey":"Turkey",
    "Indonesia":"Indonesia","Korea, Republic of":"South Korea","South Korea":"South Korea",
    "France":"France","United Kingdom":"United Kingdom","Singapore":"Singapore",
    "Japan":"Japan","Canada":"Canada","Australia":"Australia",
    "Pakistan":"Pakistan","Nigeria":"Nigeria","Thailand":"Thailand",
    "Malaysia":"Malaysia","Philippines":"Philippines","Mexico":"Mexico",
    "Argentina":"Argentina","Colombia":"Colombia","Poland":"Poland",
    "Czech Republic":"Czech Republic","Hungary":"Hungary","Bulgaria":"Bulgaria",
    "Belarus":"Belarus","Kazakhstan":"Kazakhstan","Egypt":"Egypt",
    "South Africa":"South Africa","Kenya":"Kenya"
  };

  function project(lng, lat, W, H) {
    const x = (lng + 180) / 360 * W;
    const latR = lat * Math.PI / 180;
    const mercN = Math.log(Math.tan(Math.PI/4 + latR/2));
    const y = H/2 - (mercN * W / (2 * Math.PI));
    return [x, y];
  }

  async function loadGeo() {
    if (geoData) return geoData;
    const r = await fetch("/world.geojson");
    geoData = await r.json();
    return geoData;
  }

  function drawCountry(ctx, coords, type, W, H) {
    const rings = type === "Polygon" ? [coords[0]] : coords.map(p => p[0]);
    for (const ring of rings) {
      ctx.beginPath();
      let first = true;
      for (const [lng, lat] of ring) {
        if (lat < -85 || lat > 85) continue;
        const [x, y] = project(lng, lat, W, H);
        first ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
        first = false;
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }

  async function render(canvas, geoRows, onClickFn) {
    if (onClickFn) clickCB = onClickFn;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Dark ocean background
    ctx.fillStyle = "#040810";
    ctx.fillRect(0, 0, W, H);

    // Subtle grid lines
    ctx.strokeStyle = "rgba(57,208,192,0.04)";
    ctx.lineWidth = 0.5;
    for (let lat = -60; lat <= 80; lat += 30) {
      const [,y] = project(0, lat, W, H);
      ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke();
    }
    for (let lng = -150; lng <= 180; lng += 30) {
      const [x] = project(lng, 0, W, H);
      ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke();
    }

    const geo = await loadGeo();
    const hitMap = new Map(geoRows.map(g => [g.country, g]));
    const maxA   = Math.max(...geoRows.map(g => g.attacks), 1);

    // Draw all countries — attackers highlighted, others dimmed
    for (const feature of geo.features) {
      const raw  = feature.properties.name;
      const norm = NAME_MAP[raw] || raw;
      const hit  = hitMap.get(norm);
      const {type, coordinates} = feature.geometry;

      if (hit) {
        const pct = hit.attacks / maxA;
        // Color intensity based on attack count — NOT too dark so borders stay visible
        ctx.fillStyle   = `rgba(248,81,73,${0.12 + pct * 0.3})`;
        ctx.strokeStyle = `rgba(248,81,73,${0.5  + pct * 0.4})`;
        ctx.lineWidth   = 0.7;
      } else {
        ctx.fillStyle   = "rgba(30,50,70,0.5)";
        ctx.strokeStyle = "rgba(57,208,192,0.12)";
        ctx.lineWidth   = 0.3;
      }
      try { drawCountry(ctx, coordinates, type, W, H); } catch {}
    }

    // Draw SMALL dots on top — positioned at country centroid, sized by attacks
    // Kept small so they don't cover the country shape
    for (const g of geoRows) {
      if (!g.lat && !g.lng) continue;
      const [x, y] = project(g.lng, g.lat, W, H);
      const r = Math.max(4, Math.min(12, 4 + (g.attacks / maxA) * 9));

      // Subtle glow — reduced size
      const grd = ctx.createRadialGradient(x, y, 0, x, y, r * 2.5);
      grd.addColorStop(0, "rgba(248,81,73,0.35)");
      grd.addColorStop(1, "rgba(248,81,73,0)");
      ctx.beginPath(); ctx.arc(x, y, r * 2.5, 0, Math.PI*2);
      ctx.fillStyle = grd; ctx.fill();

      // Core dot — small and crisp
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI*2);
      ctx.fillStyle = "#f85149";
      ctx.shadowBlur = 6; ctx.shadowColor = "#f85149";
      ctx.fill(); ctx.shadowBlur = 0;

      // White ring
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI*2);
      ctx.strokeStyle = "rgba(255,255,255,0.7)";
      ctx.lineWidth = 1; ctx.stroke();

      // Label — only for top attackers to avoid clutter
      if (g.attacks >= maxA * 0.25) {
        const label = `${g.country} ${g.attacks}`;
        ctx.font = "bold 10px Inter, system-ui";
        const tw = ctx.measureText(label).width;
        // Position label to the right, but keep it inside canvas
        const lx = Math.min(x + r + 5, W - tw - 4);
        const ly = y + 3;
        // Background pill
        ctx.fillStyle = "rgba(4,8,16,0.78)";
        ctx.beginPath();
        ctx.roundRect ? ctx.roundRect(lx-2, ly-11, tw+4, 14, 3) : ctx.fillRect(lx-2, ly-11, tw+4, 14);
        ctx.fill();
        ctx.fillStyle = "#e6edf3";
        ctx.fillText(label, lx, ly);
      }
    }

    // Equator label
    const [,eqY] = project(0, 0, W, H);
    ctx.strokeStyle = "rgba(57,208,192,0.1)";
    ctx.setLineDash([4,6]); ctx.lineWidth = 0.7;
    ctx.beginPath(); ctx.moveTo(0,eqY); ctx.lineTo(W,eqY); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "rgba(57,208,192,0.35)"; ctx.font = "9px system-ui";
    ctx.fillText("Equator", 5, eqY - 3);

    // Register click handler
    canvas._cb && canvas.removeEventListener("click", canvas._cb);
    canvas._cb = e => {
      const rect = canvas.getBoundingClientRect();
      const mx = (e.clientX - rect.left) * (W / rect.width);
      const my = (e.clientY - rect.top)  * (H / rect.height);
      let closest = null, closestD = Infinity;
      for (const g of geoRows) {
        if (!g.lat && !g.lng) continue;
        const [x, y] = project(g.lng, g.lat, W, H);
        const d = Math.sqrt((mx-x)**2 + (my-y)**2);
        const r = Math.max(4, Math.min(12, 4 + (g.attacks / maxA) * 9));
        if (d < r * 4 && d < closestD) { closestD = d; closest = g; }
      }
      if (closest && clickCB) clickCB(closest);
    };
    canvas.addEventListener("click", canvas._cb);
    canvas.style.cursor = "crosshair";
  }

  return { render };
})();
