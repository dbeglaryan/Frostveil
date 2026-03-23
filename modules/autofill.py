"""
Frostveil Autofill Extraction — extract saved form data, addresses, credit cards.

Extracts from Chromium 'Web Data' and Firefox formhistory.
"""
import sqlite3, json
from pathlib import Path
from . import utils, crypto

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_autofill(browser, path, meta, rows)
        _extract_chromium_credit_cards(browser, path, meta, rows)
        _extract_chromium_addresses(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_autofill(path, meta, rows)
    return rows

def _extract_chromium_autofill(browser, path, meta, rows):
    webdata = path.parent / "Web Data"
    tmp = utils.safe_copy(webdata)
    if not tmp:
        return
    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        cur.execute("""
            SELECT name, value, count, date_created, date_last_used
            FROM autofill ORDER BY date_last_used DESC
        """)
        for name, value, count, created, last_used in cur.fetchall():
            rows.append({
                **meta, "browser": browser, "artifact": "autofill",
                "profile": str(path.parent),
                "url": "",
                "title": f"{name}={value}",
                "visit_count": count,
                "visit_time_utc": utils.utc_from_webkit(last_used),
                "extra": json.dumps({
                    "field_name": name,
                    "field_value": value,
                    "created": utils.utc_from_webkit(created),
                })
            })
        con.close()
        utils.log_line(f"Autofill extracted from {webdata}")
    except Exception as e:
        utils.log_line(f"Error autofill {browser}: {e}")

def _extract_chromium_credit_cards(browser, path, meta, rows):
    webdata = path.parent / "Web Data"
    tmp = utils.safe_copy(webdata)
    if not tmp:
        return

    master_key = crypto.get_chromium_master_key(path.parent)

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        cur.execute("""
            SELECT name_on_card, expiration_month, expiration_year,
                   card_number_encrypted, date_modified, origin, use_count, use_date
            FROM credit_cards
        """)
        for name, exp_m, exp_y, card_enc, modified, origin, use_count, use_date in cur.fetchall():
            card_num = ""
            if card_enc and master_key:
                result = crypto.decrypt_chromium_blob(card_enc, master_key)
                if result:
                    # Mask card number for safety — show only last 4
                    card_num = f"****-****-****-{result[-4:]}" if len(result) >= 4 else "<decrypted>"
                else:
                    card_num = "<decryption_failed>"
            elif card_enc:
                card_num = "<encrypted:no_key>"

            rows.append({
                **meta, "browser": browser, "artifact": "credit_card",
                "profile": str(path.parent),
                "url": origin or "",
                "title": name or "",
                "visit_count": use_count,
                "visit_time_utc": utils.utc_from_webkit(use_date),
                "extra": json.dumps({
                    "card_number": card_num,
                    "expiration": f"{exp_m}/{exp_y}",
                    "modified": utils.utc_from_webkit(modified),
                })
            })
        con.close()
    except Exception as e:
        utils.log_line(f"Error credit_cards {browser}: {e}")

def _extract_chromium_addresses(browser, path, meta, rows):
    webdata = path.parent / "Web Data"
    tmp = utils.safe_copy(webdata)
    if not tmp:
        return
    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        # Try newer schema first, fall back to older
        try:
            cur.execute("""
                SELECT company_name, street_address, city, state, zipcode,
                       country_code, date_modified, use_count, use_date
                FROM autofill_profiles
            """)
            for company, street, city, state, zipcode, country, modified, use_count, use_date in cur.fetchall():
                full_addr = ", ".join(filter(None, [street, city, state, zipcode, country]))
                rows.append({
                    **meta, "browser": browser, "artifact": "address",
                    "profile": str(path.parent),
                    "url": "",
                    "title": company or full_addr[:60],
                    "visit_count": use_count,
                    "visit_time_utc": utils.utc_from_webkit(use_date),
                    "extra": json.dumps({
                        "address": full_addr,
                        "company": company or "",
                        "modified": utils.utc_from_webkit(modified),
                    })
                })
        except Exception:
            pass  # Table may not exist
        con.close()
    except Exception as e:
        utils.log_line(f"Error addresses {browser}: {e}")

def _extract_firefox_autofill(path, meta, rows):
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        fh = prof / "formhistory.sqlite"
        tmp = utils.safe_copy(fh)
        if not tmp:
            continue
        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("""
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory ORDER BY lastUsed DESC
            """)
            for fn, val, times, first, last in cur.fetchall():
                rows.append({
                    **meta, "browser": "firefox", "artifact": "autofill",
                    "profile": str(prof),
                    "url": "",
                    "title": f"{fn}={val}",
                    "visit_count": times,
                    "visit_time_utc": utils.utc_from_unix(last),
                    "extra": json.dumps({
                        "field_name": fn,
                        "field_value": val,
                        "first_used": utils.utc_from_unix(first),
                    })
                })
            con.close()
        except Exception as e:
            utils.log_line(f"Error autofill firefox {prof}: {e}")
