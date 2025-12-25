import whois
import requests
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import pdf_report_generator_m

# VIRUS TOTAL
def virus_total_analysis(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("https://www.virustotal.com/gui/home/url")
        page.fill('input#urlSearchInput', target)
        page.click('button#searchUrlButton')
        page.wait_for_timeout(6000)

        score = page.inner_text("div#positives") + page.inner_text("div#positives + div").strip()

        detections = []
        for engine in page.query_selector_all("span.engine-name"):
            engine_id = engine.get_attribute("id")
            if not engine_id:
                continue

            result_el = page.query_selector(f"span#{engine_id.replace('engine', 'engine-text')}")
            if not result_el:
                continue

            result = result_el.inner_text().strip()
            if result.lower() not in ["clean", "undetected", "harmless", "unrated"]:
                detections.append({
                    "vendor": engine.inner_text().strip(),
                    "result": result
                })

        browser.close()

        return {"score": score, "detections": detections}

# WHOIS
def whois_analysis(target):
    try:
        info = whois.whois(target)

        updated = info.updated_date
        if isinstance(updated, list):
            updated = max(updated)

        return {
            "domain": info.domain_name,
            "last_update": updated,
            "created": info.creation_date,
            "expiration": info.expiration_date,
            "registrar": info.registrar,
            "registrant": info.registrant_name,
            "name_servers": info.name_servers,
        }

    except Exception:
        return "NOT FOUND"
    except Exception:
        return "NOT FOUND"

# WHERE GOES
def where_goes_analysis(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("https://wheregoes.com/")

        #agree_btn = page.locator('button:has-text("Agree")')
        #if agree_btn.count() > 0:
        #    agree_btn.first.click()

        page.fill('input#url', target)
        page.wait_for_timeout(5000)
        page.locator('#form_button').click(force=True)
        page.wait_for_timeout(5000)

        result_url = page.url
        browser.close()

    soup = BeautifulSoup(requests.get(result_url).content, "html.parser")

    where_goes_info = []
    for textarea in soup.find_all("textarea"):
        text = textarea.get_text().replace("|", "")
        if "http" in text:
            start = text.find("http")
            end = text.find("\n", start)
            if (end == -1): # end of line if there is no \n
                end = len(text)
            link = text[start:end].strip()
            if link not in where_goes_info:
                where_goes_info.append(link)

    return where_goes_info

# DNSDUMPSTER
def parse_dnsdumpster_table(raw_rows):
    records = []

    if not raw_rows or len(raw_rows) < 2:
        return records

    for row in raw_rows[1:]:  # skip header
        if len(row) < 6:
            continue

        host = row[0].strip()

        # IP
        ip = row[1].split("\n")[0].strip()

        # ASN + subnet
        asn_lines = [l.strip() for l in row[2].split("\n") if l.strip()]
        asn = " ".join(asn_lines).replace("ASN:", "").strip()

        # ASN name + country
        asn_name = " ".join(
            l.strip() for l in row[3].split("\n") if l.strip()
        )

        # OPEN SERVICES
        services_lines = [
            l.strip()
            for l in row[4].split("\n")
            if l.strip()
        ]
        open_services = "\n".join(services_lines) if services_lines else "none"

        records.append({
            "host": host,
            "ip": ip,
            "asn": asn,
            "asn_name": asn_name,
            "open_services": open_services
        })

    return records
    
def dnsdumpster_analysis(target):
    with sync_playwright() as p:
        target_sanitized = target.replace("http://", "")
        target_sanitized = target.replace("https://", "")
        target_sanitized = target_sanitized.split("/")[0]
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("https://dnsdumpster.com/")
        page.fill("input#target", target_sanitized)
        page.click('button:has-text("Start Test!")')
        page.wait_for_timeout(6000)

        # Helper - table extraction
        def get_table_rows(locator):
            rows = []
            table = page.locator(locator)
            tr_elements = table.locator("tr").all()
            for tr in tr_elements:
                cells = tr.locator("th, td").all()
                row = [c.inner_text().strip() for c in cells]
                rows.append(row)
            return rows

        a_raw = get_table_rows("#a_rec_table")
        mx_raw = get_table_rows('text=MX Records >> xpath=./following-sibling::table[1]')
        ns_raw = get_table_rows('text=NS Records >> xpath=./following-sibling::table[1]')

        txt_cells = page.locator(
            'text=TXT Records >> xpath=./following-sibling::table[1]//td'
        ).all()
        txt_records = [c.inner_text().strip() for c in txt_cells]

        browser.close()
    
    a_records = parse_dnsdumpster_table(a_raw)
    mx_records = parse_dnsdumpster_table(mx_raw)
    ns_records = parse_dnsdumpster_table(ns_raw)

    return {
        "a_records": a_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "txt_records": txt_records
    }

def analysis(target, tools):
    print("\033[92m[*] Analysis started\033[0m")

    virus_total_info = virus_total_analysis(target) if tools[0] else None
    whois_info = whois_analysis(target) if tools[1] else None
    dnsdumpster_info = dnsdumpster_analysis(target) if tools[2] else None
    where_goes_info = where_goes_analysis(target) if tools[3] else None

    pdf_report_generator_m.generate_report(
        target,
        tools,
        virus_total_info,
        whois_info,
        dnsdumpster_info,
        where_goes_info
    )

    print("\033[92m[+] Analysis done\033[0m")