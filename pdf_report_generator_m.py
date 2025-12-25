from fpdf import FPDF
from datetime import datetime
from pathlib import Path

def safe(text):
    if text is None:
        return ""
    return text.encode("ascii", errors="replace").decode("ascii")

def mc(pdf, text, h=5):
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, h, txt=safe(text))

# for dnsdumpster output
def write_dns_records(pdf, title, records):
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 5, title, ln=True)

    if not records:
        pdf.set_font("Helvetica", size=9)
        mc(pdf, "No records found")
        pdf.ln(3)
        return

    pdf.set_font("Helvetica", size=9)

    for r in records:
        mc(pdf, f"Host: {r.get('host')}")
        mc(pdf, f"IP: {r.get('ip')}")
        mc(pdf, f"Reverse: {r.get('reverse')}")
        mc(pdf, f"ASN: {r.get('asn')} {r.get('asn_name')}")
        
        open_services = r.get("open_services")
        if open_services:
            mc(pdf, f"Open services:")
            mc(pdf, open_services)
        else:
            mc(pdf, "Open services: none")

        pdf.ln(2)


def generate_report(target, tools, virus_total, whois, dnsdumpster, where_goes):

    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style = "B", size = 20)
    pdf.cell(200, 5, txt=f"Results for {target}", ln = True, align='C')

    # VIRUS TOTAL
    if tools[0]:
        pdf.ln(10)
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(200, 5, txt="VIRUS TOTAL", ln=True, align='L')
        pdf.set_font("Helvetica", size=10)

        score = virus_total.get("score", "N/A")
        mc(pdf, f"Score: {score}")

        mc(pdf, "Detections:")
        detections = virus_total.get("detections", [])
        if detections and isinstance(detections, list):
            for det in detections:
                if isinstance(det, dict):
                    vendor = det.get("vendor", "Unknown")
                    result = det.get("result", "Unknown")
                    mc(pdf, f" - {vendor}: {result}")
                else:
                    mc(pdf, f" - {str(det)}")  # pokud je to seznam nebo řetězec
        else:
            mc(pdf, "No detections found")

    # WHOIS
    if tools[1]:
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, txt="WHOIS", ln=True)
        pdf.set_font("Helvetica", size=10)

        if not whois or "error" in whois:
            mc(pdf, "WHOIS data not available")
        else:
            mc(pdf, f"Domain: {whois.get('domain')}")
            mc(pdf, f"Registrar: {whois.get('registrar')}")
            mc(pdf, f"Created: {whois.get('created')}")

            last_update = whois.get("last_update")
            if last_update:
                mc(pdf, f"Last update: {last_update}")

            mc(pdf, f"Expiration: {whois.get('expiration')}")
            mc(pdf, f"Registrant: {whois.get('registrant')}")
            mc(pdf, f"Name servers: {whois.get('name_servers')}")
    
    # DNSDUMPSTER
    if tools[2]:
        pdf.ln(10)
        pdf.set_font("Helvetica", style="B", size=13)
        pdf.cell(200, 5, txt="DNSDUMPSTER", ln=True, align='L')

        pdf.set_font("Helvetica", size=10)

        if dnsdumpster and isinstance(dnsdumpster, dict):
            write_dns_records(pdf, "A RECORDS", dnsdumpster.get("a_records"))
            write_dns_records(pdf, "MX RECORDS", dnsdumpster.get("mx_records"))
            write_dns_records(pdf, "NS RECORDS", dnsdumpster.get("ns_records"))

            # TXT Records – každý záznam na jeden řádek
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 5, txt="TXT RECORDS", ln=True)

            pdf.set_font("Helvetica", "", 9)
            for txtrec in dnsdumpster.get("txt_records", []):
                mc(pdf, txtrec, 6)
            pdf.ln(3)
        else:
            pdf.multi_cell(0, 6, txt="DNSDumpster data missing")
    
    # WHERE GOES
    if tools[3]:
        pdf.ln(10)
        pdf.set_font("Helvetica", style = "B", size = 13)
        pdf.cell(200, 5, txt="WHERE GOES", ln = True, align='L')
        pdf.set_font("Helvetica", size = 10)
        if where_goes:
            i = 1
            for u in where_goes:
                pdf.multi_cell(
                    0,
                    5,
                    txt=f"{i}. {safe(u)}",
                    new_x="LMARGIN",
                    new_y="NEXT"
                )
                i += 1
        else:
            pdf.multi_cell(0, 5, txt="No URLs found")

    file_name = f"{dt_string}_{target}"
    file_name = file_name.replace("http://", "")
    file_name = file_name.replace("https://", "")
    file_name = file_name.replace("/", "-")
    file_name = file_name.replace(".", "-")

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    pdf.output(output_dir / f"{file_name}.pdf")