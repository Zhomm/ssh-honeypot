"""
IP Geolocation
==============
Looks up each unique attacker IP using ip-api.com (free, no API key needed).
Results are cached in the 'geo' table — already-known IPs are never re-queried.
Rate limited to ~42 requests/minute to stay within the free tier limit of 45/min.

Usage:
  python3 geo.py            # geolocate all new IPs
  python3 geo.py --stats    # print country and ASN statistics
"""

import sqlite3
import requests
import time
import argparse
from datetime import datetime, timezone


DB_FILE  = "honey.db"
API_URL  = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,org,as,query"
DELAY    = 1.4


def init_geo_table(con):
    con.execute("""
        CREATE TABLE IF NOT EXISTS geo (
            ip           TEXT PRIMARY KEY,
            country      TEXT,
            country_code TEXT,
            region       TEXT,
            city         TEXT,
            org          TEXT,
            asn          TEXT,
            is_private   INTEGER DEFAULT 0,
            api_error    TEXT,
            lookup_time  TEXT
        )
    """)
    con.commit()


def is_private(ip):
    """Return True for RFC1918 / loopback / link-local addresses."""
    private = [
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "0.", "169.254.", "::1", "fc", "fd"
    ]
    return any(ip.startswith(p) for p in private)


def lookup(ip):
    """Call ip-api.com for a single IP. Returns a data dict."""
    try:
        r = requests.get(API_URL.format(ip=ip), timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return {
                "country":      d.get("country"),
                "country_code": d.get("countryCode"),
                "region":       d.get("regionName"),
                "city":         d.get("city"),
                "org":          d.get("org"),
                "asn":          d.get("as"),
                "api_error":    None
            }
        return {"api_error": d.get("message", "unknown error")}
    except requests.Timeout:
        return {"api_error": "timeout"}
    except Exception as e:
        return {"api_error": str(e)}


def pending_ips(con):
    """Return IPs in logs that are not yet in the geo table."""
    rows = con.execute("""
        SELECT DISTINCT l.ip
        FROM logs l
        LEFT JOIN geo g ON l.ip = g.ip
        WHERE g.ip IS NULL AND l.ip IS NOT NULL
    """).fetchall()
    return [r[0] for r in rows]


def save_geo(con, ip, data):
    con.execute("""
        INSERT OR REPLACE INTO geo
            (ip, country, country_code, region, city, org, asn,
             is_private, api_error, lookup_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        data.get("country"),
        data.get("country_code"),
        data.get("region"),
        data.get("city"),
        data.get("org"),
        data.get("asn"),
        data.get("is_private", 0),
        data.get("api_error"),
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    con.commit()


def run_lookup():
    con = sqlite3.connect(DB_FILE)
    init_geo_table(con)

    ips = pending_ips(con)
    if not ips:
        print("[*] No new IPs to geolocate.")
        con.close()
        return

    print(f"[*] IPs to geolocate: {len(ips)}")
    print(f"[*] Estimated time: ~{len(ips) * DELAY:.0f}s\n")

    for i, ip in enumerate(ips, 1):
        if is_private(ip):
            save_geo(con, ip, {"is_private": 1})
            print(f"  [{i}/{len(ips)}] {ip} → private address, skipped")
            continue

        data = lookup(ip)

        if data.get("api_error"):
            print(f"  [{i}/{len(ips)}] {ip} → ERROR: {data['api_error']}")
        else:
            loc = f"{data.get('city', '?')}, {data.get('country', '?')}"
            print(f"  [{i}/{len(ips)}] {ip} → {loc} | {data.get('org', '?')}")

        save_geo(con, ip, data)

        if i < len(ips):
            time.sleep(DELAY)

    print(f"\n[*] Done. {len(ips)} IPs geolocated.")
    con.close()


def show_stats():
    con = sqlite3.connect(DB_FILE)

    print("\n=== TOP 10 ATTACKING COUNTRIES ===")
    rows = con.execute("""
        SELECT g.country, g.country_code,
               COUNT(DISTINCT l.ip)                                  as unique_ips,
               COUNT(CASE WHEN l.type='auth_attempt' THEN 1 END)     as attempts
        FROM logs l
        JOIN geo g ON l.ip = g.ip
        WHERE g.country IS NOT NULL
        GROUP BY g.country
        ORDER BY attempts DESC
        LIMIT 10
    """).fetchall()
    for country, code, n_ip, attempts in rows:
        print(f"  {code:4} {country:25} {n_ip:4} unique IPs   {attempts:6} attempts")

    print("\n=== TOP 10 ASNs / ORGANISATIONS ===")
    rows = con.execute("""
        SELECT g.org,
               COUNT(DISTINCT l.ip)                              as unique_ips,
               COUNT(CASE WHEN l.type='auth_attempt' THEN 1 END) as attempts
        FROM logs l
        JOIN geo g ON l.ip = g.ip
        WHERE g.org IS NOT NULL
        GROUP BY g.org
        ORDER BY attempts DESC
        LIMIT 10
    """).fetchall()
    for org, n_ip, attempts in rows:
        print(f"  {str(org):45} {n_ip:3} IPs  {attempts:6} attempts")

    print("\n=== TOTALS ===")
    row = con.execute("""
        SELECT COUNT(DISTINCT ip), COUNT(*), MIN(timestamp), MAX(timestamp)
        FROM logs
    """).fetchone()
    print(f"  Unique IPs:    {row[0]}")
    print(f"  Total events:  {row[1]}")
    print(f"  First event:   {row[2]}")
    print(f"  Last event:    {row[3]}")

    con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stats", action="store_true",
                        help="Show statistics instead of running lookups")
    args = parser.parse_args()
    show_stats() if args.stats else run_lookup()
