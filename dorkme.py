#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
## =====================================================================]
##  DorkMe - Custom google dork mass search with generated report        ]
##                                                                       ]
##              Latest additons before release...                        ]
##  1) proxy chaining - isp and mobile recommended for captcha(s)        ] 
##  2) csv+html export - dual output                                     ]
##  3) configuration for pages per dork - hl=en&num="???"                 ]      
##  4) added more agents for rotatioh                                    ]
##  5) perfected RPS limiter - token bucket                              ]
##  6) 204 endpoint connectivty test                                     ]
##                                                                       ]
##  NOTE: I'm not liable with what you do with this script, if you       ]
##  chose to scan for vuln(s) or exploitable web apps and act on them..  ]
##  Well that was your choice and not mine and was not this scripts      ]
##  intedned use. I used it to find scammer ads and do a mass report.    ]
##  We all have our premeditated intentions though. Do you kiddo. <3     ]
## =====================================================================]

import os, re, sys, time, random, urllib.parse, threading, csv
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from configparser import ConfigParser

import requests
from bs4 import BeautifulSoup

# [*] Files & constants 
DEFAULT_CONFIG_FILE = "config.ini"
DEFAULT_DORKS_FILE  = "dorks_scams.txt"
DEFAULT_REPORT_DIR  = "reports"
PROXIES_FILE        = "proxies.txt"

REQUEST_TIMEOUT = 14
RESULTS_PER_QUERY = 12
GOOGLE_EXTRA_PARAMS = "hl=en&num=20"

USER_AGENTS = [
    # [*] Chrome 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",

    # [*] Firefox 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",

    # [*] Safari 
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",

    # [*] Edge 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",

    # [*] iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",

    # [*] Android 
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",

    # [*] Misc
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 OPR/113.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Brave/127.0.0.0",
]

# Minimal-data connectivity endpoints (204)
CONNECT_TEST_URLS = [
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
]

PROXY_TEST_LIMIT_DEFAULT = 10  # how many proxies to test quickly
PROXY_TEST_TIMEOUT = 5         # seconds

def ua() -> str: return random.choice(USER_AGENTS)
def utcnow(fmt="%Y-%m-%d %H:%M:%SZ"): return datetime.now(timezone.utc).strftime(fmt)
def html_escape(s: str) -> str: return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def ensure_dir(p: str): os.makedirs(p, exist_ok=True)

# [*] Token bucket (global RPS limiter) 
class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = max(0.01, float(rate_per_sec))
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def take(self):
        while True:
            with self.lock:
                now = time.monotonic()
                delta = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + delta * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(min(wait, 0.25))

# [*] Per-host limiter 
class PerHostLimiter:
    def __init__(self, per_host_cap: int):
        self.cap = max(1, int(per_host_cap))
        self.lock = threading.Lock()
        self.host_sems: Dict[str, threading.Semaphore] = {}

    @staticmethod
    def host_for(url: str) -> str:
        try:
            return urllib.parse.urlparse(url).netloc or "unknown"
        except Exception:
            return "unknown"

    def acquire(self, url: str):
        host = self.host_for(url)
        with self.lock:
            sem = self.host_sems.get(host)
            if sem is None:
                sem = threading.Semaphore(self.cap)
                self.host_sems[host] = sem
        sem.acquire()
        return host, sem

# [*] Config 
def load_config(path: str) -> ConfigParser:
    cfg = ConfigParser()
    if os.path.exists(path):
        cfg.read(path, encoding="utf-8")
    else:
        cfg["run"] = {
            "open_sockets": "8",
            "per_host_cap": "2",
            "rps": "0.5",
            "burst": "2",
            "pages_per_dork": "1",
            "use_proxies": "false",
            "use_serpapi": "false",
            "serpapi_key": "",
            "dorks_file": DEFAULT_DORKS_FILE,
            "report_dir": DEFAULT_REPORT_DIR,
            "report_format": "html",  # html | csv | both
        }
        with open(path, "w", encoding="utf-8") as f:
            cfg.write(f)
    return cfg

def recommend_values() -> Dict[str, str]:
    cores = os.cpu_count() or 4
    ram_gb = None
    try:
        import psutil  # optional
        ram_gb = int(psutil.virtual_memory().total / (1024**3))
    except Exception:
        pass
    open_sockets = min(12, max(4, cores * 2))
    per_host_cap = min(4, max(2, (cores // 2) or 2))
    rps = 0.5
    burst = 2
    pages_per_dork = 1  # recommend 1–3
    return {
        "cores": str(cores),
        "ram": (f"{ram_gb}GB" if ram_gb is not None else "unknown RAM"),
        "open_sockets": str(open_sockets),
        "per_host_cap": str(per_host_cap),
        "rps": str(rps),
        "burst": str(burst),
        "pages_per_dork": str(pages_per_dork),
    }

def prompt_yesno(prompt: str, default: Optional[bool]=None) -> bool:
    s = input(prompt).strip().lower()
    if not s and default is not None:
        return default
    return s in ("y","yes","1","true")

def prompt_update_config(cfg: ConfigParser, path: str):
    rec = recommend_values()
    run = cfg["run"] if "run" in cfg else cfg.setdefault("run", {})

    print("\nUpdate settings? Press Enter to keep current values.")
    print(f"Detected: {rec['cores']} CPU cores, RAM: {rec['ram']}")

    def ask_int(key, label, hint, rec_val):
        cur = run.get(key, str(rec_val))
        s = input(f"{label} — {hint} [{cur}] (recommend {rec_val}): ").strip()
        if s:
            try:
                int(s)
                run[key] = s
            except ValueError:
                print("  (!) Invalid integer, keeping previous.")

    def ask_float(key, label, hint, rec_val):
        cur = run.get(key, str(rec_val))
        s = input(f"{label} — {hint} [{cur}] (recommend {rec_val}): ").strip()
        if s:
            try:
                float(s)
                run[key] = s
            except ValueError:
                print("  (!) Invalid number, keeping previous.")

    def ask_choice(key, label, choices, rec_val):
        cur = run.get(key, rec_val)
        s = input(f"{label} [{cur}] (choices: {', '.join(choices)}): ").strip().lower()
        if s and s in choices:
            run[key] = s

    ask_int("open_sockets",   "Global open connections", "Total concurrent requests (keeps CPU sane)", rec["open_sockets"])
    ask_int("per_host_cap",   "Per-host cap",            "Max concurrent requests to the same domain", rec["per_host_cap"])
    ask_float("rps",          "Requests per second",     "Average global pace (token bucket)",         rec["rps"])
    ask_int("burst",          "Burst size",              "Max requests at once when tokens are full",  rec["burst"])
    ask_int("pages_per_dork", "Pages per dork",          "How many Google result pages (20 results/page)", rec["pages_per_dork"])

    # Proxies & SerpAPI
    curp = run.get("use_proxies", "false")
    run["use_proxies"] = "true" if prompt_yesno(f"Use proxy chain from {PROXIES_FILE}? (y/n) [current: {curp}] ", None) else "false"

    curs = run.get("use_serpapi", "false")
    use_serp = prompt_yesno(f"Use Google via SerpAPI? (y/n) [current: {curs}] ", None)
    run["use_serpapi"] = "true" if use_serp else "false"
    if use_serp:
        key = input("SERPAPI key (leave blank to keep current): ").strip()
        if key:
            run["serpapi_key"] = key

    # Dorks/report locations
    dfile = input(f"Dorks file path [{run.get('dorks_file', DEFAULT_DORKS_FILE)}]: ").strip()
    if dfile:
        run["dorks_file"] = dfile
    rdir = input(f"Report directory [{run.get('report_dir', DEFAULT_REPORT_DIR)}]: ").strip()
    if rdir:
        run["report_dir"] = rdir

    # Report format prompt (html/csv/both)
    ask_choice("report_format", "Report format", ["html","csv","both"], run.get("report_format","html"))

    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    print(f"[config] Saved changes to {path}\n")

# [*] Proxies 
def load_proxies(path: str = PROXIES_FILE) -> List[str]:
    if not os.path.exists(path): return []
    out=[]
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s=line.strip()
            if s and not s.startswith("#"):
                out.append(s)
    return out

def proxies_dict(proxy_url: Optional[str]) -> Optional[Dict[str,str]]:
    if not proxy_url: return None
    return {"http": proxy_url, "https": proxy_url}

# [*] Dork file parsing 
def parse_dorks_file(path: str) -> List[Tuple[str, List[str]]]:
    sections=[]
    title=None
    q=[]
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line=raw.rstrip()
            if line.startswith("##"):
                if title is not None: sections.append((title, q))
                title=line.lstrip("#").strip()
                q=[]
            else:
                s=line.strip()
                if not s or s.startswith("#"): continue
                q.append(s)
        if title is not None: sections.append((title, q))
    return sections

# [*] Google helpers 
def make_google_url_from_query(query: str, start: int = 0, extra_query: str = GOOGLE_EXTRA_PARAMS) -> str:
    if query.lower().startswith("http"):
        # If it's already a URL, we still might need to append start= for pagination
        url = query
        parsed = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(parsed.query)
        q["start"] = [str(start)]
        qstr = urllib.parse.urlencode({k: v[0] if isinstance(v, list) else v for k, v in q.items()})
        return urllib.parse.urlunparse(parsed._replace(query=qstr))
    base = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
    parts = [extra_query, f"start={start}"] if extra_query else [f"start={start}"]
    return base + ("&" + "&".join(parts) if parts else "")

def clean_google_redirect(href: str) -> Optional[str]:
    if not href: return None
    if href.startswith("/url?"):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        return q.get("q", [None])[0]
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return None

def parse_google_serp_html(html: str) -> List[Tuple[str,str]]:
    soup = BeautifulSoup(html, "html.parser")
    results = []
    for h3 in soup.select("a h3"):
        link = h3.parent if h3.parent and h3.parent.name == "a" else None
        if not link: continue
        href = link.get("href")
        if not href: continue
        title = h3.get_text(" ", strip=True) or href
        url = clean_google_redirect(href)
        if url: results.append((title, url))
        if len(results) >= RESULTS_PER_QUERY: break
    if len(results) < RESULTS_PER_QUERY:
        for a in soup.select("a"):
            href = a.get("href")
            if not href: continue
            url = clean_google_redirect(href)
            if not url: continue
            title = a.get_text(" ", strip=True) or url
            results.append((title[:120], url))
            if len(results) >= RESULTS_PER_QUERY: break
    seen=set(); dedup=[]
    for t,u in results:
        if u not in seen:
            seen.add(u)
            dedup.append((t,u))
    return dedup

def looks_blocked(text: str) -> bool:
    t = (text or "").lower()
    return any(s in t for s in [
        "unusual traffic from your computer",
        "our systems have detected",
        "sorry, but your computer",
        "consent.google.com",
        "verify you are a human"
    ])

# [*] Runner 
class Runner:
    def __init__(self, cfg: ConfigParser):
        run=cfg["run"]
        self.open_sockets = max(1, int(run.get("open_sockets","8")))
        self.per_host_cap = max(1, int(run.get("per_host_cap","2")))
        self.rps          = max(0.01, float(run.get("rps","0.5")))
        self.burst        = max(1, int(run.get("burst","2")))
        self.pages_per_dork = max(1, int(run.get("pages_per_dork","1")))

        self.use_proxies  = run.get("use_proxies","false").lower()=="true"
        self.use_serpapi  = run.get("use_serpapi","false").lower()=="true"
        self.serpapi_key  = run.get("serpapi_key","").strip()
        self.dorks_file   = run.get("dorks_file", DEFAULT_DORKS_FILE)
        self.report_dir   = run.get("report_dir", DEFAULT_REPORT_DIR)
        self.report_format= run.get("report_format", "html").lower()

        if self.use_serpapi and not self.serpapi_key:
            print("[warn] use_serpapi=true but no serpapi_key; disabling SerpAPI.")
            self.use_serpapi=False

        self.proxies = load_proxies() if self.use_proxies else []
        self._p_lock = threading.Lock()
        self._p_idx  = 0

        ensure_dir(self.report_dir)

        # HTTP session & limits
        self.session=requests.Session()
        adapter=requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=self.open_sockets, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.bucket = TokenBucket(self.rps, self.burst)
        self.perhost = PerHostLimiter(self.per_host_cap)

    def _next_proxy(self)->Optional[str]:
        if not self.proxies: return None
        with self._p_lock:
            p=self.proxies[self._p_idx % len(self.proxies)]
            self._p_idx+=1
            return p

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self.bucket.take()
        _, sem = self.perhost.acquire(url)
        try:
            return self.session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        except Exception:
            return None
        finally:
            sem.release()

    # [*] Backends with pagination 
    def google_html_search_pages(self, query_or_url: str) -> List[Tuple[str,str]]:
        allres=[]
        for page_idx in range(self.pages_per_dork):
            start = page_idx * 20
            url = make_google_url_from_query(query_or_url, start=start)
            r = self.request(
                "GET", url,
                headers={"User-Agent": ua(), "Accept-Language":"en-US,en;q=0.9"},
                proxies=proxies_dict(self._next_proxy()),
            )
            if not r or r.status_code != 200: 
                continue
            if looks_blocked(r.text): 
                break
            res = parse_google_serp_html(r.text)
            if not res:
                # No more results likely
                break
            allres.extend(res)
        # dedup across pages
        seen=set(); out=[]
        for (t,u) in allres:
            if u not in seen:
                seen.add(u)
                out.append((t,u))
        return out

    def serpapi_search_pages(self, query_or_url: str) -> List[Tuple[str,str]]:
        # Extract query from URL if needed
        if query_or_url.lower().startswith("http"):
            parsed = urllib.parse.urlparse(query_or_url)
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            query = urllib.parse.unquote_plus(q) if q else query_or_url
        else:
            query = query_or_url
        allres=[]
        for page_idx in range(self.pages_per_dork):
            start = page_idx * 20
            params = {"engine":"google","q":query,"num":"20","hl":"en","api_key":self.serpapi_key,"start":start}
            url = "https://serpapi.com/search"
            r = self.request("GET", url, params=params, headers={"User-Agent": ua()}, proxies=proxies_dict(self._next_proxy()))
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            res=[]
            for item in (data.get("organic_results") or []):
                link=item.get("link"); title=(item.get("title") or link)
                if link: res.append((title, link))
                if len(res)>=RESULTS_PER_QUERY: break
            if not res:
                break
            allres.extend(res)
        # dedup
        seen=set(); out=[]
        for (t,u) in allres:
            if u not in seen:
                seen.add(u)
                out.append((t,u))
        return out

    def _run_one(self, q_or_url: str)->List[Tuple[str,str]]:
        if self.use_serpapi:
            res=self.serpapi_search_pages(q_or_url)
            if res: return res
        return self.google_html_search_pages(q_or_url)

    def run_section(self, title: str, queries: List[str]) -> Tuple[str, List[str], List[Tuple[str,str,str]]]:
        """
        Returns (title, cleaned_queries, results_by_row)
        results_by_row: list of (query, result_title, result_url)
        """
        print(f"\n[Section] {title}  (items: {len(queries)})")
        cleaned=[s.strip() for s in queries if s.strip()]
        results_rows: List[Tuple[str,str,str]]=[]
        with ThreadPoolExecutor(max_workers=self.open_sockets) as ex:
            futs=[]
            for q in cleaned:
                print(f"  → queued: {q}")
                futs.append(ex.submit(self._run_logged, q))
            for f in as_completed(futs):
                q, res = f.result()
                for (t,u) in res:
                    results_rows.append((q,t,u))
        return title, cleaned, results_rows

    def _run_logged(self, q: str) -> Tuple[str, List[Tuple[str,str]]]:
        print(f"    searching: {q}")
        out=self._run_one(q)
        print(f"      -> {len(out)} result(s)" if out else "      -> 0 results (blocked/none)")
        return q, out

# [*] Reports 
def build_html(sections_out: List[Tuple[str, List[str], List[Tuple[str,str,str]]]])->str:
    now=utcnow()
    css="""
    body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px}
    h1{font-size:22px;margin-bottom:0}.meta{color:#666;margin-bottom:18px}
    h2{font-size:18px;border-bottom:1px solid #eee;padding-bottom:4px;margin-top:24px}
    ol{padding-left:18px}li{margin:6px 0}code{background:#f6f8fa;padding:2px 4px;border-radius:4px}
    """
    out=[f"<!doctype html><html><head><meta charset='utf-8'><title>DorkMe. Report</title><style>{css}</style></head><body>"]
    out.append("<h1>DorkMe. Report</h1>")
    out.append(f"<div class='meta'>Generated: <b>{html_escape(now)}</b></div>")
    for title, queries, rows in sections_out:
        out.append(f"<h2>{html_escape(title)}</h2>")
        out.append("<h3>Queries</h3><ol>")
        for q in queries:
            g_url = q if q.lower().startswith("http") else f"https://www.google.com/search?q={urllib.parse.quote(q)}"
            out.append(f"<li><code>{html_escape(q)}</code> — <a target='_blank' href='{html_escape(g_url)}'>Open on Google</a></li>")
        out.append("</ol>")
        out.append("<h3>Results</h3>")
        if not rows:
            out.append("<p><em>No results captured.</em></p>")
        else:
            out.append("<ol>")
            seen=set()
            for (_, t, u) in rows:
                if u in seen: continue
                seen.add(u)
                out.append(f"<li><a target='_blank' href='{html_escape(u)}'>{html_escape(t)}</a><br><code>{html_escape(u)}</code></li>")
            out.append("</ol>")
    out.append("</body></html>")
    return "\n".join(out)

def save_csv(path: str, sections_out: List[Tuple[str, List[str], List[Tuple[str,str,str]]]]):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Section","Query","ResultTitle","ResultURL"])
        for (title, _, rows) in sections_out:
            for (q, t, u) in rows:
                w.writerow([title, q, t, u])

# [Connectivity Tests] #
def _http_204_get(url: str, proxy: Optional[str] = None, timeout: int = PROXY_TEST_TIMEOUT) -> Tuple[bool, float, int]:
    """
    Try a quick HTTP GET to a known 204/no-content URL.
    Returns (success, elapsed_time, status_code).
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    t0 = time.time()
    try:
        r = requests.get(url, proxies=proxies, timeout=timeout, headers={"User-Agent": ua()})
        elapsed = time.time() - t0
        if r.status_code == 204 or r.status_code == 200:
            return True, elapsed, r.status_code
        return False, elapsed, r.status_code
    except Exception:
        return False, time.time() - t0, -1

def quick_connectivity_check() -> bool:
    """
    Try a couple of 204 endpoints without proxy.
    Returns True if any succeed.
    """
    print("\n[check] Baseline connectivity (no proxy):")
    ok_any = False
    for url in CONNECT_TEST_URLS:
        ok, t, code = _http_204_get(url, proxy=None)
        status = "OK" if ok else "FAIL"
        print(f"  • {url} -> {status} (code={code}, {t:.2f}s)")
        ok_any = ok_any or ok
        if ok:  # one success is enough to consider baseline OK
            break
    return ok_any

def quick_serpapi_check(api_key: str) -> bool:
    """
    Minimal SerpAPI query (1 result). Returns True if HTTP 200 & JSON parse OK.
    """
    if not api_key:
        print("[check] SerpAPI: no key provided.")
        return False
    print("[check] SerpAPI key check (1-result query):")
    try:
        r = requests.get(
            "https://serpapi.com/search",
            params={"engine":"google","q":"connectivity check","num":"1","hl":"en","api_key": api_key},
            headers={"User-Agent": ua()},
            timeout=PROXY_TEST_TIMEOUT,
        )
        ok = (r.status_code == 200)
        try:
            _ = r.json()
        except Exception:
            ok = False
        print(f"  • /search -> {'OK' if ok else 'FAIL'} (code={r.status_code})")
        return ok
    except Exception:
        print("  • /search -> FAIL (exception)")
        return False

def quick_proxy_check(proxies: List[str], limit: int = PROXY_TEST_LIMIT_DEFAULT, save_csv_path: Optional[str] = None) -> None:
    """
    Probe first N proxies against a 204 endpoint.
    Prints a table and optionally saves CSV (proxy, ok, status, latency_s).
    """
    if not proxies:
        print("[check] Proxy list is empty; skipping proxy tests.")
        return
    test_urls = [CONNECT_TEST_URLS[0]]  # one endpoint is enough
    rows = []
    print(f"[check] Testing first {min(limit, len(proxies))} proxies with 204 endpoint:")
    for i, proxy in enumerate(proxies[:limit], 1):
        ok, t, code = _http_204_get(test_urls[0], proxy=proxy)
        print(f"  {i:02d}. {proxy} -> {'OK' if ok else 'FAIL'} (code={code}, {t:.2f}s)")
        rows.append((proxy, "OK" if ok else "FAIL", code, f"{t:.3f}"))
    if save_csv_path:
        ensure_dir(os.path.dirname(save_csv_path))
        with open(save_csv_path, "w", encoding="utf-8", newline="") as f:
            import csv as _csv
            w = _csv.writer(f)
            w.writerow(["proxy","status","http_code","latency_s"])
            for r in rows: w.writerow(r)
        print(f"[check] Proxy test CSV saved: {save_csv_path}")

# [*] CLI 
def main():
    print(r"""
________                __      _____          
\______ \   ___________|  | __ /     \   ____  
 |    |  \ /  _ \_  __ \  |/ //  \ /  \_/ __ \ 
 |    `   (  <_> )  | \/    </    Y    \  ___/ 
/_______  /\____/|__|  |__|_ \____|__  /\___  >
        \/                  \/       \/     \/
	[DorkMe: Google dork search automator]
""")

    cfg=load_config(DEFAULT_CONFIG_FILE)
    if prompt_yesno("Review/update settings? (y/n): ", default=False):
        prompt_update_config(cfg, DEFAULT_CONFIG_FILE)
        cfg=load_config(DEFAULT_CONFIG_FILE)

    # Optional quick connectivity tests (minimal data, 204 connectivity test)
    if prompt_yesno("Run quick connectivity tests (baseline, SerpAPI, proxies)? (y/n): ", default=False):
        baseline_ok = quick_connectivity_check()
        run = cfg["run"]
        serp_ok = quick_serpapi_check(run.get("serpapi_key","").strip()) if run.get("use_serpapi","false").lower()=="true" else None

        # If proxies enabled, test first N and save a CSV report
        if run.get("use_proxies","false").lower()=="true":
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            proxy_csv = os.path.join(run.get("report_dir", DEFAULT_REPORT_DIR), f"proxy_check_{ts}.csv")
            test_proxies = load_proxies()
            quick_proxy_check(test_proxies, limit=PROXY_TEST_LIMIT_DEFAULT, save_csv_path=proxy_csv)

    run=cfg["run"]
    dorks_file=run.get("dorks_file", DEFAULT_DORKS_FILE)
    report_dir=run.get("report_dir", DEFAULT_REPORT_DIR)
    report_format=run.get("report_format","html").lower()

    # Allow user to adjust report format at start
    fmt_in = input(f"Report format [current: {report_format}] (html/csv/both, Enter to keep): ").strip().lower()
    if fmt_in in ("html","csv","both"):
        run["report_format"]=fmt_in
        with open(DEFAULT_CONFIG_FILE, "w", encoding="utf-8") as f:
            cfg.write(f)
        report_format=fmt_in

    if not os.path.exists(dorks_file):
        print(f"[error] Dorks file not found: {dorks_file}")
        print("Use '## Title' lines with unnumbered dorks/URLs beneath.")
        sys.exit(1)

    runner=Runner(cfg)
    print(f"[start] open_sockets={runner.open_sockets} | per_host_cap={runner.per_host_cap} "
          f"| rps={runner.rps} burst={runner.burst} | pages_per_dork={runner.pages_per_dork} "
          f"| proxies={'on' if runner.use_proxies else 'off'} ({len(runner.proxies)} loaded) "
          f"| serpapi={'on' if runner.use_serpapi else 'off'} | format={report_format}")

    sections=parse_dorks_file(dorks_file)
    if not sections:
        print(f"[error] No sections found in {dorks_file}. Use '## Title' and dorks/URLs beneath.")
        sys.exit(1)

    outputs=[]
    for title, queries in sections:
        outputs.append(runner.run_section(title, queries))

    ensure_dir(report_dir)
    ts=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    if report_format in ("html","both"):
        html_path=os.path.join(report_dir, f"report_{ts}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(build_html(outputs))
        print(f"[saved] HTML: {html_path}")

    if report_format in ("csv","both"):
        csv_path=os.path.join(report_dir, f"report_{ts}.csv")
        save_csv(csv_path, outputs)
        print(f"[saved] CSV : {csv_path}")

    print("\n[done] All reports saved.")

if __name__=="__main__":
    try:
        import bs4  # noqa
    except Exception:
        print("Tip: install deps with  pip install requests beautifulsoup4\n")
    main()
