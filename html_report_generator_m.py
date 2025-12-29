from datetime import datetime
from pathlib import Path
import html

def safe(text):
    if text is None:
        return ""
    return html.escape(str(text))

def generate_report(target, tools, virus_total, whois, dnsdumpster, where_goes):
    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Report for {safe(target)}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ text-align: center; }}
            h2 {{ margin-top: 30px; }}
            h3 {{ margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            ul, ol {{ margin-left: 20px; }}
        </style>
    </head>
    <body>
        <h1>Results for {safe(target)}</h1>
    """

    # VIRUS TOTAL
    if tools[0] and virus_total is not None:
        html_content += "<h2>VirusTotal</h2>"
        score = virus_total.get("score", "N/A")
        html_content += f"<p><b>Score:</b> {safe(score)}</p>"
        
        html_content += "<p><b>Detections:</b></p><ul>"
        detections = virus_total.get("detections", [])
        if detections and isinstance(detections, list):
            for det in detections:
                if isinstance(det, dict):
                    vendor = det.get("vendor", "Unknown")
                    result = det.get("result", "Unknown")
                    html_content += f"<li>{safe(vendor)}: {safe(result)}</li>"
                else:
                    html_content += f"<li>{safe(det)}</li>"
        else:
            html_content += "<li>No detections found</li>"
        html_content += "</ul>"

    # WHOIS
    if tools[1]:
        html_content += "<h2>WHOIS</h2>"
        if not whois or "error" in whois:
            html_content += "<p>WHOIS data not available</p>"
        else:
            html_content += "<ul>"
            html_content += f"<li>Domain: {safe(whois.get('domain'))}</li>"
            html_content += f"<li>Registrar: {safe(whois.get('registrar'))}</li>"
            html_content += f"<li>Created: {safe(whois.get('created'))}</li>"
            html_content += f"<li>Last update: {safe(whois.get('last_update'))}</li>"
            html_content += f"<li>Expiration: {safe(whois.get('expiration'))}</li>"
            html_content += f"<li>Registrant: {safe(whois.get('registrant'))}</li>"
            html_content += f"<li>Name servers: {safe(', '.join(whois.get('name_servers', [])))}</li>"
            html_content += "</ul>"

    # DNSDUMPSTER
    if tools[2]:
        html_content += "<h2>DNSDumpster</h2>"

        def render_dns_table(title, records):
            if not records:
                return f"<p><b>{title}:</b> No records found</p>"
            table_html = f"<h3>{title}</h3><table><tr><th>Host</th><th>IP</th><th>Reverse</th><th>ASN</th><th>Open Services</th></tr>"
            for r in records:
                open_services = safe(r.get("open_services", "none"))
                table_html += f"<tr><td>{safe(r.get('host'))}</td><td>{safe(r.get('ip'))}</td><td>{safe(r.get('reverse'))}</td><td>{safe(r.get('asn'))} {safe(r.get('asn_name'))}</td><td>{open_services}</td></tr>"
            table_html += "</table>"
            return table_html

        if dnsdumpster and isinstance(dnsdumpster, dict):
            html_content += render_dns_table("A Records", dnsdumpster.get("a_records", []))
            html_content += render_dns_table("MX Records", dnsdumpster.get("mx_records", []))
            html_content += render_dns_table("NS Records", dnsdumpster.get("ns_records", []))

            # TXT records
            txt_records = dnsdumpster.get("txt_records", [])
            html_content += "<h3>TXT Records</h3>"
            if txt_records:
                html_content += "<ul>"
                for txtrec in txt_records:
                    html_content += f"<li>{safe(txtrec)}</li>"
                html_content += "</ul>"
            else:
                html_content += "<p>No TXT records found</p>"
        else:
            html_content += "<p>DNSDumpster data missing</p>"

    # WHERE GOES
    if tools[3]:
        html_content += "<h2>Where Goes</h2>"
        if where_goes:
            html_content += "<ol>"
            for u in where_goes:
                html_content += f"<li>{safe(u)}</li>"
            html_content += "</ol>"
        else:
            html_content += "<p>No URLs found</p>"

    html_content += """
    </body>
    </html>
    """

    file_name = f"{dt_string}_{target}"
    file_name = file_name.replace("http://", "").replace("https://", "").replace("/", "-").replace(".", "-")
    
    output_dir = Path("reports/html")
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / f"{file_name}.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\033[92m[+] HTML report saved as {file_name}.html\033[0m")