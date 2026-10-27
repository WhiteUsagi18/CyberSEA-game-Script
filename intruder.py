#!/usr/bin/env python3
"""
Mini Burp-Intruder-style fuzzer for CTF use.

=====================================================================
 QUICK REFERENCE — how to use this
=====================================================================

Two modes:
  1. single_position() / --mode sniper
       -> like Burp "Sniper": ONE payload set, ONE marker §x§
  2. two_position()    / --mode bomb | pitchfork
       -> two markers §x§ and §y§
          bomb      = every combination of payload_x * payload_y (Burp Cluster Bomb)
          pitchfork = pairs payload_x[i] with payload_y[i], same-length files only

---------------------------------------------------------------------
 PAYLOAD FILES
---------------------------------------------------------------------
Plain .txt file, one payload per line:
    payload1
    payload2
    payload3
Blank lines and lines starting with '#' are skipped automatically.
Loaded with load_payloads("file.txt") -> returns a list[str].

---------------------------------------------------------------------
 WHERE TO PUT THE MARKER (§x§ / §y§)
---------------------------------------------------------------------
The marker can go ANYWHERE in the request — it gets substituted in the
URL, in --data (the POST body string), and in --header values. Put it
wherever the real unknown value sits:

  URL query param   : --url "http://target/api?cx=§x§"
  POST body field   : --data "user=admin&pass=§x§"
  JSON body         : --data '{"user":"admin","token":"§x§"}'
                       --header "Content-Type: application/json"
  Header / token    : --header "X-Auth-Token: §x§"
  Cookie            : --cookie "session: §x§"

You can mix positions across url/data/header freely in --mode bomb or
pitchfork, e.g. §x§ in --data and §y§ in --header at the same time.

---------------------------------------------------------------------
 CLI EXAMPLES
---------------------------------------------------------------------
# GET, single position (sniper)
python3 intruder.py --url "http://target.ctf/api?cx=§x§" \\
    --payload payload.txt --mode sniper --match-status 200

# POST, marker in body (sniper)
python3 intruder.py --url "http://target.ctf/login" --method POST \\
    --data "user=admin&pass=§x§" \\
    --payload payload.txt --mode sniper --match-status 200

# POST, marker in a header, e.g. bruteforcing an auth token (sniper)
python3 intruder.py --url "http://target.ctf/login" --method POST \\
    --data "user=admin&pass=1234" \\
    --header "X-Auth-Token: §x§" \\
    --payload payload.txt --mode sniper --match-status 200

# Two positions, every combination (bomb / cluster bomb)
python3 intruder.py --url "http://target.ctf/upload" --method POST \\
    --data "script=§x§" --header "X-Filename: §y§" \\
    --payload scripts.txt,images.txt --mode bomb --match-status 200

# Two positions, paired line-by-line (pitchfork, files must match length)
python3 intruder.py --url "http://target.ctf/api?a=§x§&b=§y§" \\
    --payload payload.txt,payload2.txt --mode pitchfork --match-status 200

---------------------------------------------------------------------
 USEFUL FLAGS
---------------------------------------------------------------------
  --method POST                  HTTP method (default GET)
  --header "Key: Value"          repeatable, markers allowed in the value
  --cookie "name: value"         repeatable, markers allowed in the value
  --match-status 200             only show responses with this status code
  --match-len 1234               only show responses with this content length
  --match-text "flag{"           only show responses containing this substring
  --show-all                     print every attempt, not just matches
  --threads 20                   concurrent requests (default 10, start low)
  --timeout 5                    per-request timeout in seconds (default 8)
  --proxy http://127.0.0.1:8080  route through Burp so you can watch traffic too
  --marker-x / --marker-y        change markers from default §x§ / §y§

Run `python3 intruder.py --help` any time for the full flag list.

Can also be imported and used as a library — see single_position() and
two_position() docstrings below for the Python-API version of all of this.
=====================================================================
"""

import argparse
import itertools
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()  # quiet SSL warnings for lab targets


# --------------------------------------------------------------------------
# Wordlist loader — reads payloads from a .txt file, one payload per line
# --------------------------------------------------------------------------
def load_payloads(path, encoding="utf-8", strip=True, skip_empty=True, skip_comments=True):
    """
    Load a payload list from a text file, one payload per line.

    strip          : strip whitespace/newline from each line
    skip_empty     : drop blank lines
    skip_comments  : drop lines starting with '#' (handy for annotated wordlists)

    Returns a list[str]. For huge wordlists (rockyou-sized), you can instead
    pass a generator to single_position/two_position directly, e.g.:
        payloads=(line.strip() for line in open("wordlist.txt", encoding="utf-8"))
    but note two_position's clusterbomb mode needs payloads_x/payloads_y as
    real lists (it reuses them for every combination), so load_payloads()
    is the simplest choice in practice.
    """
    out = []
    with open(path, "r", encoding=encoding, errors="ignore") as f:
        for line in f:
            if strip:
                line = line.strip("\n\r")
                if strip is True:
                    line = line.strip()
            if skip_empty and not line:
                continue
            if skip_comments and line.lstrip().startswith("#"):
                continue
            out.append(line)
    return out


# --------------------------------------------------------------------------
# Core single-request sender
# --------------------------------------------------------------------------
def send_request(method, url, headers=None, data=None, params=None,
                  cookies=None, timeout=8, allow_redirects=False, proxies=None):
    """
    Thin wrapper around requests so both modes share the same request logic.
    `proxies` lets you route through Burp itself, e.g. {"http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"} if you want to watch traffic in Burp too.
    """
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=params,
            cookies=cookies,
            timeout=timeout,
            verify=False,
            allow_redirects=allow_redirects,
            proxies=proxies,
        )
        return resp
    except requests.RequestException as e:
        return e


def _substitute(template, marker, value):
    """Replace a single marker token (e.g. '§x§') with value in a string."""
    if template is None:
        return None
    return template.replace(marker, str(value))


def _substitute_all(method, url, headers, data, params, marker, value):
    """Apply substitution across every field that might contain the marker."""
    new_url = _substitute(url, marker, value)
    new_headers = {k: _substitute(v, marker, value) for k, v in (headers or {}).items()}
    new_data = _substitute(data, marker, value) if isinstance(data, str) else data
    if isinstance(data, dict):
        new_data = {k: _substitute(v, marker, value) if isinstance(v, str) else v
                    for k, v in data.items()}
    new_params = None
    if isinstance(params, dict):
        new_params = {k: _substitute(v, marker, value) if isinstance(v, str) else v
                      for k, v in params.items()}
    return new_url, new_headers, new_data, new_params


# --------------------------------------------------------------------------
# 1) SINGLE POSITION  — like Burp Sniper with one marker §x§
# --------------------------------------------------------------------------
def single_position(method, url, payloads, marker="§x§",
                     headers=None, data=None, params=None, cookies=None,
                     threads=10, timeout=8, proxies=None,
                     match_status=None, match_len=None, match_text=None,
                     show_all=False):
    """
    Bruteforce ONE position, e.g. url = "http://target/login?user=§x§"

    payloads   : iterable of strings (or a generator / wordlist iterator)
    marker     : the placeholder token to replace, default "§x§"
    match_*    : optional filters to highlight "interesting" responses
                 (status code, content length, or substring in body)
    show_all   : if True, print every result, not just matches

    Returns a list of dicts: {"payload": ..., "status": ..., "len": ..., "resp": ...}
    """
    results = []

    def worker(payload):
        u, h, d, p = _substitute_all(method, url, headers, data, params, marker, payload)
        resp = send_request(method, u, headers=h, data=d, params=p,
                             cookies=cookies, timeout=timeout, proxies=proxies)
        if isinstance(resp, Exception):
            return {"payload": payload, "status": "ERR", "len": 0,
                    "resp": None, "error": str(resp)}
        return {"payload": payload, "status": resp.status_code,
                "len": len(resp.content), "resp": resp}

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(worker, pl): pl for pl in payloads}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            is_match = True
            if match_status is not None:
                is_match = is_match and (r["status"] == match_status)
            if match_len is not None:
                is_match = is_match and (r["len"] == match_len)
            if match_text is not None and r["resp"] is not None:
                is_match = is_match and (match_text in r["resp"].text)

            if show_all or (is_match and (match_status or match_len or match_text)):
                print(f"[{r['status']}] len={r['len']:<6} payload={r['payload']!r}")

    return results


# --------------------------------------------------------------------------
# 2) TWO POSITIONS — like Burp Cluster Bomb (all combos) or Pitchfork (paired)
# --------------------------------------------------------------------------
def two_position(method, url, payloads_x, payloads_y,
                  marker_x="§x§", marker_y="§y§",
                  mode="clusterbomb",  # "clusterbomb" = all combinations, "pitchfork" = pair index-by-index
                  headers=None, data=None, params=None, cookies=None,
                  threads=10, timeout=8, proxies=None,
                  match_status=None, match_len=None, match_text=None,
                  show_all=False):
    """
    Bruteforce TWO positions, e.g. url = "http://target/upload?script=§x§&img=§y§"

    mode="clusterbomb": every combination of payloads_x * payloads_y (like Burp Cluster Bomb)
    mode="pitchfork"  : pairs payloads_x[i] with payloads_y[i] (like Burp Pitchfork,
                        lists must be same length)

    Returns a list of dicts: {"x": ..., "y": ..., "status": ..., "len": ..., "resp": ...}
    """
    results = []

    if mode == "clusterbomb":
        combos = itertools.product(payloads_x, payloads_y)
    elif mode == "pitchfork":
        combos = zip(payloads_x, payloads_y)
    else:
        raise ValueError("mode must be 'clusterbomb' or 'pitchfork'")

    def worker(pair):
        x_val, y_val = pair
        u, h, d, p = _substitute_all(method, url, headers, data, params, marker_x, x_val)
        u, h, d, p = _substitute_all(method, u, h, d, p, marker_y, y_val)
        resp = send_request(method, u, headers=h, data=d, params=p,
                             cookies=cookies, timeout=timeout, proxies=proxies)
        if isinstance(resp, Exception):
            return {"x": x_val, "y": y_val, "status": "ERR", "len": 0,
                    "resp": None, "error": str(resp)}
        return {"x": x_val, "y": y_val, "status": resp.status_code,
                "len": len(resp.content), "resp": resp}

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(worker, pair): pair for pair in combos}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            is_match = True
            if match_status is not None:
                is_match = is_match and (r["status"] == match_status)
            if match_len is not None:
                is_match = is_match and (r["len"] == match_len)
            if match_text is not None and r["resp"] is not None:
                is_match = is_match and (match_text in r["resp"].text)

            if show_all or (is_match and (match_status or match_len or match_text)):
                print(f"[{r['status']}] len={r['len']:<6} x={r['x']!r} y={r['y']!r}")

    return results


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _parse_kv_list(items):
    """Turn ['Key: Value', 'Key2: Value2'] into a dict. Used for --header / --cookie."""
    out = {}
    for item in items or []:
        if ":" not in item:
            raise ValueError(f"Expected 'Key: Value', got {item!r}")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def main():
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="intruder.py",
        description="Mini Burp-Intruder-style fuzzer. Mark fuzz spots in --url/--data/--header "
                     "with §x§ (sniper mode) or §x§ and §y§ (bomb mode).",
    )
    ap.add_argument("--url", required=True, help="Target URL, e.g. 'http://host/api?cx=§x§'")
    ap.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    ap.add_argument(
        "--payload", required=True,
        help="Payload file(s). One file for --mode sniper. "
             "Two comma-separated files (x,y) for --mode bomb, e.g. payload1.txt,payload2.txt",
    )
    ap.add_argument(
        "--mode", choices=["sniper", "bomb", "pitchfork"], default="sniper",
        help="sniper = single position (§x§). bomb = two positions, every combination (clusterbomb). "
             "pitchfork = two positions, paired line-by-line (payload files must be same length).",
    )
    ap.add_argument("--data", default=None, help="POST body, e.g. 'script=§x§&filename=§y§'")
    ap.add_argument(
        "--header", action="append", default=[],
        help="Extra header, 'Key: Value'. Repeatable: --header 'Cookie: a=1' --header 'X-Foo: bar'",
    )
    ap.add_argument(
        "--cookie", action="append", default=[],
        help="Cookie, 'Key: Value'. Repeatable.",
    )
    ap.add_argument("--marker", default="§x§", help="Marker for the single position in sniper mode (default §x§)")
    ap.add_argument("--marker-x", default="§x§", help="Marker for position 1 in bomb/pitchfork mode (default §x§)")
    ap.add_argument("--marker-y", default="§y§", help="Marker for position 2 in bomb/pitchfork mode (default §y§)")
    ap.add_argument("--threads", type=int, default=10, help="Concurrent requests (default: 10)")
    ap.add_argument("--timeout", type=float, default=8, help="Per-request timeout in seconds (default: 8)")
    ap.add_argument("--proxy", default=None, help="Route through a proxy, e.g. http://127.0.0.1:8080 (watch in Burp)")
    ap.add_argument("--match-status", type=int, default=None, help="Only show/flag responses with this status code")
    ap.add_argument("--match-len", type=int, default=None, help="Only show/flag responses with this content length")
    ap.add_argument("--match-text", default=None, help="Only show/flag responses containing this substring")
    ap.add_argument("--show-all", action="store_true", help="Print every attempt, not just matches")

    args = ap.parse_args()

    headers = _parse_kv_list(args.header)
    cookies = _parse_kv_list(args.cookie)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    if args.mode == "sniper":
        payload_files = [p.strip() for p in args.payload.split(",") if p.strip()]
        if len(payload_files) != 1:
            sys.exit("--mode sniper needs exactly ONE payload file in --payload")
        payloads = load_payloads(payload_files[0])

        single_position(
            method=args.method,
            url=args.url,
            payloads=payloads,
            marker=args.marker,
            headers=headers or None,
            data=args.data,
            cookies=cookies or None,
            threads=args.threads,
            timeout=args.timeout,
            proxies=proxies,
            match_status=args.match_status,
            match_len=args.match_len,
            match_text=args.match_text,
            show_all=args.show_all,
        )

    else:  # bomb (clusterbomb) or pitchfork
        payload_files = [p.strip() for p in args.payload.split(",") if p.strip()]
        if len(payload_files) != 2:
            sys.exit("--mode bomb/pitchfork needs exactly TWO comma-separated payload files in --payload, "
                      "e.g. --payload payload1.txt,payload2.txt")
        payloads_x = load_payloads(payload_files[0])
        payloads_y = load_payloads(payload_files[1])
        burp_mode = "clusterbomb" if args.mode == "bomb" else "pitchfork"

        two_position(
            method=args.method,
            url=args.url,
            payloads_x=payloads_x,
            payloads_y=payloads_y,
            marker_x=args.marker_x,
            marker_y=args.marker_y,
            mode=burp_mode,
            headers=headers or None,
            data=args.data,
            cookies=cookies or None,
            threads=args.threads,
            timeout=args.timeout,
            proxies=proxies,
            match_status=args.match_status,
            match_len=args.match_len,
            match_text=args.match_text,
            show_all=args.show_all,
        )


if __name__ == "__main__":
    main()
