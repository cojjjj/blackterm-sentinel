package dashboard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/store"
)

type Options struct {
	Addr   string
	Target string
	DBPath string
}

func Serve(opts Options) error {
	if strings.TrimSpace(opts.Addr) == "" {
		opts.Addr = "127.0.0.1:8765"
	}

	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return fmt.Errorf("invalid dashboard address %q: %w", opts.Addr, err)
	}

	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("dashboard must bind to localhost/loopback in V0.5")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexHTML))
	})

	mux.HandleFunc("/api/summary", withStore(opts.DBPath, func(s *store.Store, w http.ResponseWriter, r *http.Request) error {
		summary, err := s.DashboardSummary(opts.Target)
		if err != nil {
			return err
		}
		return writeJSON(w, summary)
	}))

	mux.HandleFunc("/api/assets", withStore(opts.DBPath, func(s *store.Store, w http.ResponseWriter, r *http.Request) error {
		assets, err := s.Assets(opts.Target)
		if err != nil {
			return err
		}
		return writeJSON(w, assets)
	}))

	mux.HandleFunc("/api/findings", withStore(opts.DBPath, func(s *store.Store, w http.ResponseWriter, r *http.Request) error {
		findings, err := s.RecentFindings(200)
		if err != nil {
			return err
		}
		return writeJSON(w, findings)
	}))

	mux.HandleFunc("/api/events", withStore(opts.DBPath, func(s *store.Store, w http.ResponseWriter, r *http.Request) error {
		events, err := s.RecentEvents(opts.Target, 200)
		if err != nil {
			return err
		}
		return writeJSON(w, events)
	}))

	mux.HandleFunc("/api/web", withStore(opts.DBPath, func(s *store.Store, w http.ResponseWriter, r *http.Request) error {
		web, err := s.LatestWebInterfaces(opts.Target)
		if err != nil {
			return err
		}
		return writeJSON(w, web)
	}))

	server := &http.Server{
		Addr:              opts.Addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("BLACKTERM // SENTINEL DASHBOARD\n")
	fmt.Printf("Target: %s\n", opts.Target)
	fmt.Printf("Open:   http://%s\n", opts.Addr)
	fmt.Printf("Press Ctrl+C to stop.\n")

	return server.ListenAndServe()
}

type storeHandler func(*store.Store, http.ResponseWriter, *http.Request) error

func withStore(dbPath string, fn storeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Open(dbPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer s.Close()

		if err := fn(s, w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func writeJSON(w http.ResponseWriter, value any) error {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BLACKTERM // SENTINEL</title>
<style>
:root{
  --bg:#07090d;--panel:#0d1118;--panel2:#101620;--line:#222c3a;
  --text:#e8edf5;--muted:#8491a4;--cyan:#79e6ff;--green:#7cffb2;
  --yellow:#ffd479;--orange:#ff9c66;--red:#ff6b7a;--purple:#b39cff;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at top,#111927 0,#07090d 40%);
color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
.wrap{max-width:1500px;margin:auto;padding:28px}
header{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:24px}
.brand h1{font-size:24px;margin:0;letter-spacing:.08em}
.brand p{color:var(--muted);margin:5px 0 0}
.status{padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;background:var(--muted)}
.dot.on{background:var(--green);box-shadow:0 0 12px var(--green)}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
.card,.panel{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
border-radius:12px;box-shadow:0 12px 30px #0005}
.card{padding:16px}
.card .label{color:var(--muted);font-size:12px}
.card .value{font-size:27px;margin-top:6px}
.panels{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin-top:14px}
.panel{padding:16px;overflow:hidden}
.panel h2{font-size:14px;letter-spacing:.08em;margin:0 0 14px}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--muted);font-weight:500;font-size:11px;padding:8px;border-bottom:1px solid var(--line)}
td{padding:9px 8px;border-bottom:1px solid #18202b;vertical-align:top}
tr:last-child td{border-bottom:0}
.tag{display:inline-block;padding:2px 7px;border-radius:999px;border:1px solid var(--line);font-size:11px}
.CRITICAL,.HIGH{color:var(--red)} .MEDIUM{color:var(--orange)} .LOW{color:var(--yellow)} .INFO{color:var(--cyan)}
.ACTIVE,.NEW{color:var(--green)} .STALE{color:var(--yellow)} .OFFLINE{color:var(--red)}
.muted{color:var(--muted)}
.scroll{max-height:420px;overflow:auto}
.event{padding:10px 0;border-bottom:1px solid #18202b}
.event:last-child{border-bottom:0}
.event .time{color:var(--muted);font-size:11px}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.refresh{color:var(--muted);font-size:11px;margin-top:12px}
@media(max-width:1000px){.grid{grid-template-columns:repeat(3,1fr)}.panels{grid-template-columns:1fr}}
@media(max-width:600px){.grid{grid-template-columns:repeat(2,1fr)}header{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<div class="wrap">
<header>
<div class="brand">
<h1>BLACKTERM // SENTINEL</h1>
<p>NETWORK STATE INTELLIGENCE · OBSERVE. REMEMBER. DETECT.</p>
</div>
<div class="status"><span id="monitorDot" class="dot"></span><span id="monitorText">Loading...</span></div>
</header>

<section class="grid">
<div class="card"><div class="label">ASSETS</div><div class="value" id="assets">—</div></div>
<div class="card"><div class="label">ACTIVE</div><div class="value ACTIVE" id="active">—</div></div>
<div class="card"><div class="label">SERVICES</div><div class="value" id="services">—</div></div>
<div class="card"><div class="label">FINDINGS</div><div class="value" id="findings">—</div></div>
<div class="card"><div class="label">HIGH+</div><div class="value HIGH" id="high">—</div></div>
<div class="card"><div class="label">EVENTS</div><div class="value" id="eventsCount">—</div></div>
</section>

<section class="panels">
<div class="panel">
<h2>ASSET INVENTORY</h2>
<div class="scroll"><table>
<thead><tr><th>IP</th><th>HOSTNAME</th><th>TYPE</th><th>STATE</th><th>SEEN</th></tr></thead>
<tbody id="assetRows"></tbody>
</table></div>
</div>

<div class="panel">
<h2>RECENT EVENTS</h2>
<div id="events" class="scroll"></div>
</div>

<div class="panel">
<h2>SECURITY FINDINGS</h2>
<div class="scroll"><table>
<thead><tr><th>SEV</th><th>HOST</th><th>FINDING</th></tr></thead>
<tbody id="findingRows"></tbody>
</table></div>
</div>

<div class="panel">
<h2>WEB INTERFACES</h2>
<div class="scroll"><table>
<thead><tr><th>HOST</th><th>TYPE</th><th>INTERFACE</th></tr></thead>
<tbody id="webRows"></tbody>
</table></div>
</div>
</section>

<div class="refresh">Auto-refresh every 5 seconds · local dashboard only</div>
</div>
<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
}[c]));

const get = async p => {
  const r = await fetch(p, {cache:'no-store'});
  if (!r.ok) throw new Error(await r.text());
  return r.json();
};

const fmt = t => t ? new Date(t).toLocaleString() : '—';

async function refresh() {
  try {
    const [s,a,f,e,w] = await Promise.all([
      get('/api/summary'),
      get('/api/assets'),
      get('/api/findings'),
      get('/api/events'),
      get('/api/web')
    ]);

    assets.textContent = s.assets;
    active.textContent = s.active_assets;
    services.textContent = s.services;
    findings.textContent = s.findings;
    high.textContent = s.critical + s.high;
    eventsCount.textContent = s.events;

    const mon = s.monitoring || {};
    monitorDot.className = 'dot ' + (mon.active ? 'on' : '');
    monitorText.textContent = mon.active
      ? 'MONITORING ACTIVE · ' + (mon.interval / 1000000000) + 's'
      : 'MONITORING IDLE · last scan ' + fmt(s.last_scan_at);

    assetRows.innerHTML = a.map(function(x) {
      return '<tr>' +
        '<td>' + esc(x.ip) + '</td>' +
        '<td>' + esc(x.hostname || 'unknown') + '</td>' +
        '<td><span class="tag">' + esc(x.device_type || 'UNKNOWN') + '</span></td>' +
        '<td class="' + esc(x.state) + '">' + esc(x.state) + '</td>' +
        '<td>' + esc(x.observation_count) + '</td>' +
        '</tr>';
    }).join('');

    events.innerHTML = e.length ? e.map(function(x) {
      return '<div class="event">' +
        '<div><span class="' + esc(x.severity) + '">[' + esc(x.severity) + ']</span> ' + esc(x.message) + '</div>' +
        '<div class="time">' + fmt(x.created_at) + '</div>' +
        '</div>';
    }).join('') : '<div class="muted">No events recorded.</div>';

    findingRows.innerHTML = f.slice(0, 100).map(function(x) {
      return '<tr>' +
        '<td class="' + esc(x.severity) + '">' + esc(x.severity) + '</td>' +
        '<td>' + esc(x.host) + (x.port ? ':' + esc(x.port) : '') + '</td>' +
        '<td>' + esc(x.title) + '</td>' +
        '</tr>';
    }).join('');

    webRows.innerHTML = w.map(function(x) {
      const type = (x.login_indicators && x.login_indicators.length)
        ? '<span class="tag HIGH">LOGIN</span>'
        : '<span class="tag">WEB</span>';

      return '<tr>' +
        '<td>' + esc(x.hostname || x.ip) + '</td>' +
        '<td>' + type + '</td>' +
        '<td><a href="' + esc(x.url) + '" target="_blank" rel="noreferrer">' + esc(x.url) + '</a></td>' +
        '</tr>';
    }).join('');
  } catch (err) {
    monitorText.textContent = 'Dashboard error: ' + err.message;
  }
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`
