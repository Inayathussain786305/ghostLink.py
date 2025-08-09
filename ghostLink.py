#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostLink++ (single-file)
Author : Inayat Hussain (Pakistani Security Researcher)
Tagline: "There is No Place to Hide"
License: MIT
Notes: Single-file OSINT username enumerator + dork generator + optional Bing queries.
"""

import argparse
import csv
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote_plus, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Optional nice output
try:
    from termcolor import colored
except Exception:
    def colored(s, _=None):
        return s

# -------------------------
BANNER = r"""
  ____ _               _   _ _      
 / ___| |__   ___  ___| |_(_) | ___ 
| |  _| '_ \ / _ \/ __| __| | |/ _ \
| |_| | | | |  __/ (__| |_| | |  __/
 \____|_| |_|\___|\___|\__|_|_|\___|
          There is No Place to Hide
        by Inayat Hussain - (Pakistani Security Researcher)
"""

ETHICS = """
ETHICS: GhostLink is an OSINT utility for lawful, ethical research only.
Do not use for stalking, harassment, or activities that violate ToS or laws.
Keep actions logged and authorized.
"""

# -------------------------
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 24
DEFAULT_USER_AGENT = "GhostLink/4.0 (+https://github.com/inayathussain)"

# -------------------------
# Built-in platform list (100+). Use '{}' where identifier is inserted.
# This is intentionally generous and includes many common username endpoints.
# Expand or edit inline if needed.
PLATFORMS = [
    ("GitHub", "https://github.com/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("Bitbucket", "https://bitbucket.org/{}"),
    ("Gist", "https://gist.github.com/{}"),
    ("SourceForge", "https://sourceforge.net/u/{}/profile"),
    ("StackOverflow", "https://stackoverflow.com/users/{}"),
    ("StackExchange", "https://stackexchange.com/users/{}"),
    ("Reddit", "https://www.reddit.com/user/{}/"),
    ("Twitter", "https://twitter.com/{}"),
    ("X", "https://x.com/{}"),
    ("Instagram", "https://www.instagram.com/{}/"),
    ("Facebook", "https://www.facebook.com/{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
    ("Hashnode", "https://hashnode.com/@{}"),
    ("YouTube @", "https://www.youtube.com/@{}"),
    ("YouTube user", "https://www.youtube.com/user/{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("TikTok", "https://www.tiktok.com/@{}"),
    ("Pinterest", "https://www.pinterest.com/{}/"),
    ("Tumblr", "https://{}.tumblr.com"),
    ("WordPress", "https://{}.wordpress.com"),
    ("Blogger", "https://{}.blogspot.com"),
    ("Behance", "https://www.behance.net/{}"),
    ("Dribbble", "https://dribbble.com/{}"),
    ("ArtStation", "https://www.artstation.com/{}"),
    ("DeviantArt", "https://www.deviantart.com/{}"),
    ("Flickr", "https://www.flickr.com/people/{}/"),
    ("SoundCloud", "https://soundcloud.com/{}"),
    ("Mixcloud", "https://www.mixcloud.com/{}"),
    ("Anchor", "https://anchor.fm/{}"),
    ("Goodreads", "https://www.goodreads.com/{}"),
    ("Scribd", "https://www.scribd.com/{}"),
    ("Slideshare", "https://www.slideshare.net/{}"),
    ("ResearchGate", "https://www.researchgate.net/profile/{}"),
    ("Academia.edu", "https://independent.academia.edu/{}"),
    ("ORCID", "https://orcid.org/{}"),
    ("GoogleScholar", "https://scholar.google.com/citations?user={}"),
    ("Crunchbase", "https://www.crunchbase.com/person/{}"),
    ("AngelList", "https://angel.co/{}"),
    ("ProductHunt", "https://www.producthunt.com/@{}"),
    ("Patreon", "https://www.patreon.com/{}"),
    ("Ko-fi", "https://ko-fi.com/{}"),
    ("OpenSea", "https://opensea.io/{}"),
    ("Etsy", "https://www.etsy.com/people/{}"),
    ("Steam", "https://steamcommunity.com/id/{}"),
    ("Xbox", "https://account.xbox.com/en-us/profile?gamertag={}"),
    ("Keybase", "https://keybase.io/{}"),
    ("VK", "https://vk.com/{}"),
    ("Weibo", "https://weibo.com/{}"),
    ("Zhihu", "https://www.zhihu.com/people/{}"),
    ("Kaggle", "https://www.kaggle.com/{}"),
    ("HackerOne", "https://hackerone.com/{}"),
    ("Bugcrowd", "https://bugcrowd.com/{}"),
    ("HackerRank", "https://www.hackerrank.com/{}"),
    ("CodePen", "https://codepen.io/{}"),
    ("Replit", "https://replit.com/@{}"),
    ("Glitch", "https://glitch.com/~{}"),
    ("Gitee", "https://gitee.com/{}"),
    ("Gumroad", "https://gumroad.com/{}"),
    ("Vimeo", "https://vimeo.com/{}"),
    ("Dailymotion", "https://www.dailymotion.com/{}"),
    ("Letterboxd", "https://letterboxd.com/{}"),
    ("IMDb", "https://www.imdb.com/name/{}"),
    ("Trello", "https://trello.com/{}"),
    ("Notion", "https://www.notion.so/{}"),
    ("Bitly", "https://bitly.com/u/{}"),
    ("TinyLetter", "https://tinyletter.com/{}"),
    ("About.me", "https://about.me/{}"),
    ("Upwork", "https://www.upwork.com/freelancers/~{}"),
    ("Fiverr", "https://www.fiverr.com/{}"),
    ("Freelancer", "https://www.freelancer.com/u/{}"),
    ("OpenLibrary", "https://openlibrary.org/authors/{}"),
    ("Houzz", "https://www.houzz.com/user/{}"),
    ("Koo", "https://www.kooapp.com/profile/{}"),
    ("Rumble", "https://rumble.com/c/{}"),
    ("PeerTube", "https://peertube.social/@{}"),
    ("Mix", "https://mix.com/{}"),
    ("Ello", "https://ello.co/{}"),
    ("Coub", "https://coub.com/{}"),
    ("Tildes", "https://tildes.net/u/{}"),
    ("Slashdot", "https://slashdot.org/~{}"),
    ("PapersWithCode", "https://paperswithcode.com/{}"),
    ("Minds", "https://www.minds.com/{}"),
    ("WT.Social", "https://wt.social/{}"),
    ("Whois (domain try)", "https://whois.domaintools.com/{}"),
    ("Namecheap (domain try)", "https://www.namecheap.com/domains/registration/results/?domain={}"),
    ("Bitbucket (alt)", "https://bitbucket.org/{}"),
    ("Steam (alt)", "https://steamcommunity.com/profiles/{}"),
    ("Discord profile", "https://discord.com/users/{}"),
    ("Telegram t.me", "https://t.me/{}"),
    ("Telegram web", "https://web.telegram.org/k/#{}"),
    ("Slack workspace try", "https://{}.slack.com"),
    ("HubSpot contacts try", "https://app.hubspot.com/contacts/{}"),
    ("Stripe (profile try)", "https://stripe.com/{}"),
    ("Stripe dashboard try", "https://dashboard.stripe.com/{}"),
    ("Zillow profile", "https://www.zillow.com/profile/{}"),
    ("Houzz alt", "https://www.houzz.com/user/{}"),
    ("OpenSea alt", "https://opensea.io/collection/{}"),
    ("GitHub Pages (username)", "https://{}.github.io"),
    ("Shopify (store)", "https://{}.myshopify.com"),
    ("Pinterest alt", "https://in.pinterest.com/{}"),
    ("Product Hunt maker", "https://www.producthunt.com/@{}"),
    ("Crunchbase alt", "https://www.crunchbase.com/person/{}"),
    ("AngelList alt", "https://angel.co/u/{}"),
    ("ResearchGate alt", "https://www.researchgate.net/profile/{}"),
    ("Academia alt", "https://{}.academia.edu"),
    ("Medium alt", "https://{}/@{}"),  # sometimes domain-based
    # end list (approx 110 entries)
]

# -------------------------
# Utilities
def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass

# -------------------------
# HTTP session with retries
def make_session(proxy=None, insecure=False, retries=2, backoff=0.3, timeout=DEFAULT_TIMEOUT):
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    s.verify = not insecure
    s.trust_env = False
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})

    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS']))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    # wrap a simple get with timeout param later; we won't set session.timeout directly
    return s

def try_get(session, url, timeout):
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return resp
    except Exception as e:
        return e

# -------------------------
# Worker check
NEGATIVE_MARKERS = [
    "not found", "page not found", "404", "doesn't exist", "user not found",
    "no results found", "error 404", "profile not found", "we couldn't find",
    "this page isn’t available", "page unavailable", "account suspended"
]

def check_platform(session, name, template, identifier, timeout, stealth_delay=0.0, verbose=False):
    # format template carefully: some templates expect raw username, some expect domain-based
    try:
        url = template.format(quote_plus(identifier))
    except Exception:
        # try simple replace if format fails
        url = template.replace("{}", quote_plus(identifier))
    res = {"platform": name, "url": url, "status": None, "http_code": None, "latency": None, "note": ""}
    start = time.time()
    r = try_get(session, url, timeout)
    elapsed = round(time.time() - start, 3)
    res["latency"] = elapsed
    if isinstance(r, Exception):
        res["status"] = "Error"
        res["note"] = repr(r)
        if verbose:
            print(colored(f"[!] {name}: {res['note']}", "magenta"))
        if stealth_delay:
            time.sleep(stealth_delay)
        return res
    code = getattr(r, "status_code", None)
    res["http_code"] = code
    body = ""
    try:
        body = r.text.lower()
    except Exception:
        body = ""
    if code == 200:
        # heuristics to avoid false positives (sites returning 200 on fallback pages)
        if any(n in body for n in NEGATIVE_MARKERS):
            res["status"] = "Not Found"
        else:
            res["status"] = "FOUND"
    elif code in (301, 302):
        res["status"] = "POSSIBLE"
    elif code in (401, 403):
        res["status"] = "PROTECTED"
    elif code == 404:
        res["status"] = "Not Found"
    else:
        # treat others as Not Found but keep code
        res["status"] = "Not Found"
    if stealth_delay:
        time.sleep(stealth_delay)
    return res

# -------------------------
# Runner
def run_enumeration(identifier, deep=False, workers=8, timeout=DEFAULT_TIMEOUT, proxy=None, stealth=False, delay_min=0.0, delay_max=0.0, insecure=False, verbose=False):
    session = make_session(proxy=proxy, insecure=insecure, retries=2, backoff=0.3, timeout=timeout)
    # choose platforms: quick (first 25) or deep (all)
    platforms = PLATFORMS if deep else PLATFORMS[:25]
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, MAX_WORKERS)) as exe:
        futures = {}
        for (name, tmpl) in platforms:
            rand_delay = random.uniform(delay_min, delay_max) if (delay_min or delay_max) else 0
            stealth_delay = (random.uniform(0.3, 1.0) if stealth else 0) or rand_delay
            fut = exe.submit(check_platform, session, name, tmpl, identifier, timeout, stealth_delay, verbose)
            futures[fut] = name
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {"platform": futures[fut], "url": "", "status": "Error", "http_code": "", "latency": "", "note": repr(e)}
            # print only interesting statuses unless verbose
            s = res.get("status", "Unknown")
            if s == "FOUND":
                print(colored(f"[{res['platform']}] {s} -> {res['url']}", "green"))
            elif s == "POSSIBLE":
                print(colored(f"[{res['platform']}] {s} -> {res['url']}", "yellow"))
            elif s == "PROTECTED":
                print(colored(f"[{res['platform']}] {s} -> {res['url']}", "cyan"))
            else:
                if verbose:
                    print(colored(f"[{res['platform']}] {s} -> {res['url']} | {res.get('note','')}", "magenta"))
            results.append(res)
    # sort by platform
    results = sorted(results, key=lambda x: x["platform"].lower())
    return results

# -------------------------
# Save outputs
def save_outputs(identifier, results, out_dir=None, json_out=True, csv_out=True, html_out=True):
    base_ts = f"{identifier}_ghostlink_{timestamp()}"
    if out_dir:
        safe_mkdir(out_dir)
        base = os.path.join(out_dir, base_ts)
    else:
        base = base_ts
    out_files = {}
    if json_out:
        fn = base + ".json"
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        out_files["json"] = fn
    if csv_out:
        fn = base + ".csv"
        with open(fn, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["platform", "url", "status", "http_code", "latency", "note"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in ["platform", "url", "status", "http_code", "latency", "note"]})
        out_files["csv"] = fn
    if html_out:
        fn = base + ".html"
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write("<!doctype html><html><head><meta charset='utf-8'>")
                f.write(f"<title>GhostLink Report - {identifier}</title>")
                f.write("<style>body{font-family:Arial,Helvetica,sans-serif;background:#0b0b0b;color:#e6e6e6}table{border-collapse:collapse;width:100%}th,td{padding:8px;border:1px solid #222}th{background:#111}a{color:#66d9ef}</style>")
                f.write("</head><body>")
                f.write(f"<h2>GhostLink Report - {identifier}</h2>")
                f.write(f"<p>Generated: {datetime.now().isoformat()}</p>")
                f.write("<table><thead><tr><th>Platform</th><th>Status</th><th>HTTP</th><th>Latency(s)</th><th>URL</th><th>Note</th></tr></thead><tbody>")
                for r in results:
                    color = "#2ecc71" if r["status"] == "FOUND" else "#f39c12" if r["status"] == "POSSIBLE" else "#e74c3c"
                    f.write("<tr>")
                    f.write(f"<td>{r['platform']}</td>")
                    f.write(f"<td style='color:{color};font-weight:600'>{r['status']}</td>")
                    f.write(f"<td>{r.get('http_code','')}</td>")
                    f.write(f"<td>{r.get('latency','')}</td>")
                    f.write(f"<td><a href='{r['url']}' target='_blank'>{r['url']}</a></td>")
                    f.write(f"<td>{r.get('note','')}</td>")
                    f.write("</tr>")
                f.write("</tbody></table></body></html>")
            out_files["html"] = fn
        except Exception as e:
            # ignore html save error
            pass
    return out_files

# -------------------------
# Dork generation
def generate_dorks(identifier, found_results):
    dorks = []
    ident = identifier.strip()
    # simple username and variations
    dorks.append(f'"{ident}"')
    dorks.append(f'intext:"{ident}"')
    dorks.append(f'inurl:"{ident}"')
    dorks.append(f'"{ident}" filetype:pdf')
    dorks.append(f'"{ident}" filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx')
    dorks.append(f'"{ident}" "email" OR "contact"')
    # if email style
    if "@" in ident:
        local, domain = ident.split("@", 1)
        dorks.append(f'"{ident}"')
        dorks.append(f'"{local}" site:{domain}')
        dorks.append(f'site:{domain} "{local}"')
    # enrich with found domains
    for r in found_results:
        if r.get("status") == "FOUND":
            try:
                host = urlparse(r.get("url")).netloc
                if host:
                    dorks.append(f'site:{host} "{ident}"')
            except Exception:
                pass
    # paste sites & leaks
    dorks.append(f'"{ident}" site:pastebin.com OR site:ghostbin.com OR site:hastebin.com')
    # code repos
    dorks.append(f'"{ident}" site:github.com OR site:gitlab.com')
    # generic sensitive files
    dorks.append(f'"{ident}" ext:env OR ext:ini OR ext:log OR ext:sql OR ext:db')
    # dedupe
    out = []
    seen = set()
    for d in dorks:
        if d not in seen:
            out.append(d)
            seen.add(d)
    return out

# -------------------------
# Optional Bing Search wrapper (safe)
def bing_search(query, bing_key, count=5):
    if not bing_key:
        return {"error": "No Bing key provided"}
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": bing_key}
    params = {"q": query, "count": count}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": repr(e)}

# -------------------------
# CLI & main
def parse_args():
    p = argparse.ArgumentParser(prog="ghostlink", description="GhostLink++: username cross-match + dorker (single-file)")
    p.add_argument("identifier", help="username or email (e.g. johndoe or john@example.com)")
    p.add_argument("--deep", action="store_true", help="Run deep scan (all built-in platforms)")
    p.add_argument("--workers", type=int, default=8, help="Concurrent workers (default 8, max 24)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds")
    p.add_argument("--proxy", type=str, help="Proxy URL (http://... or socks5h://...)")
    p.add_argument("--delay-min", type=float, default=0.0, help="Minimum random per-request delay (s)")
    p.add_argument("--delay-max", type=float, default=0.0, help="Maximum random per-request delay (s)")
    p.add_argument("--stealth", action="store_true", help="Enable small randomized stealth delays")
    p.add_argument("--insecure", action="store_true", help="Disable SSL verification (for local intercept only!)")
    p.add_argument("--no-json", action="store_true", help="Don't save JSON output")
    p.add_argument("--no-csv", action="store_true", help="Don't save CSV output")
    p.add_argument("--no-html", action="store_true", help="Don't save HTML output")
    p.add_argument("--outdir", type=str, help="Output directory for reports")
    p.add_argument("--bing-key", type=str, help="(Optional) Bing Web Search API key to run dorks programmatically")
    p.add_argument("--bing-count", type=int, default=5, help="Bing results per dork (default 5)")
    p.add_argument("--verbose", action="store_true", help="Verbose output (print errors and all statuses)")
    return p.parse_args()

def main():
    args = parse_args()
    identifier = args.identifier.strip()
    if not identifier:
        print("Identifier required (username or email).")
        sys.exit(1)
    # print banner and ethics
    os.system("clear" if os.name != "nt" else "cls")
    print(colored(BANNER, "green"))
    print(colored(ETHICS, "magenta"))
    print(colored(f"[*] Searching identifier: {identifier}", "yellow"))
    mode = "Deep" if args.deep else "Quick"
    print(colored(f"[i] Mode: {mode} | Workers: {args.workers} | Timeout: {args.timeout}s", "cyan"))
    if args.proxy:
        print(colored(f"[i] Proxy: {args.proxy}", "cyan"))
    if args.stealth:
        print(colored("[i] Stealth delays enabled", "cyan"))
    if args.delay_min or args.delay_max:
        print(colored(f"[i] Random per-request delays: {args.delay_min}s - {args.delay_max}s", "cyan"))
    if args.insecure:
        print(colored("[!] SSL verification disabled (insecure). Only use for local testing with intercepting proxy.", "yellow"))

    # run enumeration
    results = run_enumeration(
        identifier,
        deep=args.deep,
        workers=max(1, min(args.workers, MAX_WORKERS)),
        timeout=args.timeout,
        proxy=args.proxy,
        stealth=args.stealth,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        insecure=args.insecure,
        verbose=args.verbose
    )

    # save outputs
    outdir = args.outdir or os.getcwd()
    out_files = save_outputs(
        identifier,
        results,
        out_dir=outdir,
        json_out=not args.no_json,
        csv_out=not args.no_csv,
        html_out=not args.no_html
    )

    # summary
    found = [r for r in results if r.get("status") == "FOUND"]
    poss = [r for r in results if r.get("status") == "POSSIBLE"]
    prot = [r for r in results if r.get("status") == "PROTECTED"]
    print()
    print(colored(f"[+] Scan complete. FOUND: {len(found)} | POSSIBLE: {len(poss)} | PROTECTED: {len(prot)} | TOTAL: {len(results)}", "green"))
    if out_files:
        print(colored("[+] Output files:", "cyan"))
        for k, v in out_files.items():
            print(colored(f"   - {k.upper()}: {v}", "cyan"))

    # generate dorks
    dorks = generate_dorks(identifier, results)
    dork_file = os.path.join(outdir, f"{identifier}_ghostlink_dorks_{timestamp()}.txt")
    try:
        with open(dork_file, "w", encoding="utf-8") as f:
            for d in dorks:
                f.write(d + "\n")
        print(colored(f"[+] Dorks saved to: {dork_file}", "cyan"))
    except Exception as e:
        print(colored(f"[!] Could not save dorks: {e}", "magenta"))

    # optional: query Bing (if key present)
    bing_key = args.bing_key or os.environ.get("BING_API_KEY")
    if bing_key:
        print(colored("[i] Running Bing queries (this uses your key)...", "cyan"))
        bing_results = {}
        for d in dorks:
            res = bing_search(d, bing_key, count=args.bing_count)
            # save each dork result quickly
            bing_results[d] = res
            time.sleep(1 + random.random() * 1.5)  # polite spacing
        # write bing results
        try:
            bing_out = os.path.join(outdir, f"{identifier}_ghostlink_bing_{timestamp()}.json")
            with open(bing_out, "w", encoding="utf-8") as f:
                json.dump(bing_results, f, indent=2, ensure_ascii=False)
            print(colored(f"[+] Bing results saved to: {bing_out}", "cyan"))
        except Exception as e:
            print(colored(f"[!] Could not save Bing results: {e}", "magenta"))
    else:
        print(colored("[i] No Bing key provided — generated dorks only (run them manually or supply --bing-key)", "yellow"))

    print(colored("\n[i] Done. Remember: ethical & lawful use only.", "magenta"))

if __name__ == "__main__":
    main()
