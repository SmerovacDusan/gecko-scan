import socket
from os import system, name
import analysis_m
import db_record_m

# global variables
target = ""
connection_virus_total = False
connection_whois = False
connection_dnsdumpster = False
connection_where_goes = False

virus_total = False
whois = False
dnsdumpster = False
where_goes = False
database_record = True

pdf_report = True
html_report = False


# functions
# clear command line after running the app
def clear():
    # windows
    if name == 'nt':
        _ = system('cls')
    # linux and mac
    else:
        _ = system('clear')

# gecko ascii printed at the start of the app
# This ASCII pic can be found at
# https://asciiart.website/index.php?art=animals/reptiles/lizards
def gecko_ascii():
    print("       __ \/_")
    print("      (\' \`\\")
    print("   _\, \ \\/ ")
    print("    /`\/\ \\")
    print("         \ \\    ")
    print("          \ \\/\/_")
    print("          /\ \\'\\")
    print("        __\ `\\\\")
    print("         /|`  `\\")
    print("                \\")
    print("                 \\")
    print("                  \\     ,")
    print("                   `---'  ")

    print("\033[92m Welcome to Gecko Scan!\033[0m")

# pinging web servers
def ping(host, port=80, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except Exception:
        return False

# testing sites connection using function ping()
def sites_connection():
    global connection_virus_total, connection_whois, connection_dnsdumpster, connection_where_goes
    def check_whois_server(host='whois.verisign-grs.com', port=43, timeout=3):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False
    
    print("\n----SITES CONNECTION TEST----\n")
    print("+===========================+")
    print("| Site               Status |")
    print("+===========================+")

    # coloring OK and ERROR using ANSI escape code
    if ping('virustotal.com'):
        print("| VirusTotal         \033[92mOK\033[0m     |")
        connection_virus_total = True
    else:
        print("| VirusTotal         \033[91mERROR\033[0m  |")

    if check_whois_server():
        print("| Whois              \033[92mOK\033[0m     |")
        connection_whois = True
    else:
        print("| Whois              \033[91mERROR\033[0m  |")
    
    if ping('dnsdumpster.com'):
        print("| DNSDumpster        \033[92mOK\033[0m     |")
        connection_dnsdumpster = True
    else:
        print("| DNSDumpster        \033[91mERROR\033[0m  |")

    if ping('wheregoes.com'):
        print("| WhereGoes          \033[92mOK\033[0m     |")
        connection_where_goes = True
    else:
        print("| WhereGoes          \033[91mERROR\033[0m  |")
    
    print("+===========================+")
    print("\n---------END OF TEST---------\n")

# help/command screen
def commands():
    print("\nPOSSIBLE COMMANDS:")
    print("tools               Display tools")
    print("url                 Set target")
    print("db [on|off]         Turn on/off adding records to the database (default on)")
    print("report [pdf|html]   Select report type (default PDF)")
    print("run                 Run the URL analysis with selected tools")
    print("exit                Exit from the app")
    print("help                Display this message\n")

def select_unselect(tool_name: str, selected: bool, connection: bool) -> bool:
    if not connection:
        print(f"\033[91m[!] There is no connection to {tool_name}! Check your Internet connection or wait for a while and run Gecko Scan again.\033[0m")

    if selected:
        while True:
            answer = input(f"\033[93m[?] {tool_name} already selected! Do you want to unselect it? [y/n]> \033[0m").lower()

            if answer == "y":
                print(f"\033[92m[+] {tool_name} unselected!\033[0m")
                return False
            elif answer == "n":
                print(f"\033[92m[+] {tool_name} remains selected!\033[0m")
                return True
            else:
                print("\033[91m[!] Unrecognized command\033[0m")
    else:
        print(f"\033[92m[+] {tool_name} selected!\033[0m")
        return True

# tools screen
def tools():
    global virus_total, whois, dnsdumpster, where_goes
    print("TOOLS")
    print("(Choose one or more sites. Use command exit to leave the tools screen)")
    print("+======================================================================================+")
    print("| No. | Site        | Description                                                      |")
    print("+======================================================================================+")
    print("|  1  | VirusTotal  | Service that allows you to scan files, domains, URLs for malware |\n" \
    "|     |             | and other threats                                                |")
    print("+--------------------------------------------------------------------------------------+")
    print("|  2  | Whois       | Public database that shows information about domain ownership,   |\n" \
    "|     |             | such as registrant, registrar, and registration dates            |")
    print("+--------------------------------------------------------------------------------------+")
    print("|  3  | DNSDumpster | Domain research tool that can discover hosts related to a domain |")
    print("+--------------------------------------------------------------------------------------+")
    print("|     |             | URL redirect checker follows the path of the URL.                |\n" \
    "|  4  | WhereGoes   | It will show you the full redirection path of URLs,              |\n" \
    "|     |             | shortened links, or tiny URLs                                    |")
    print("+======================================================================================+")

    # tools command line
    while True:
        choice = input("tools> ")

        if choice == "exit":
            break
        else:
            if choice == "1":
                virus_total = select_unselect("VirusTotal", virus_total, connection_virus_total)
            elif choice == "2":
                whois = select_unselect("Whois", whois, connection_whois)
            elif choice == "3":
                dnsdumpster = select_unselect("DNSDumpster", dnsdumpster, connection_dnsdumpster)
            elif choice == "4":
                where_goes = select_unselect("WhereGoes", where_goes, connection_where_goes)
            else:
                print("\033[91m[!] You must choose number between 1 and 4!\033[0m")

# url command line
# input check (enter), ask when rewriting
def url():
    global target
    while True:
        url = input("url> ")
        if url.lower() == "exit":
            print(target)
            break
        else:
            target = url.lower()
            print(f"\033[92m[+] Using: {target}\033[0m")
            break

# command line
def cli():
    global database_record, pdf_report, html_report

    while True:
        user_input = input("> ")

        if user_input == "help":
            commands()
        elif user_input == "exit":
            print("Bye! :)")
            quit()
        elif user_input == "tools":
            tools()
        elif user_input == "url":
            url()
        elif user_input == "db on":
            database_record = True
            print("\033[92m[+] Adding records to the database enabled\033[0m")
        elif user_input == "db off":
            database_record = False
            print("\033[92m[+] Adding records to the database disabled\033[0m")
        elif user_input == "report pdf":
            if pdf_report:
                pdf_report = False
                print("\033[92m[+] PDF report unselected!\033[0m")
            else:
                pdf_report = True
                print("\033[92m[+] PDF report selected!\033[0m")
        elif user_input == "report html":
            if html_report:
                html_report = False
                print("\033[92m[+] HTML report unselected!\033[0m")
            else:
                html_report = True
                print("\033[92m[+] HTML report unselected!\033[0m")
        elif user_input == "run":
            selected_tools = [virus_total, whois, dnsdumpster, where_goes]
            if target == "":
                print("\033[91m[!] URL not selected!\033[0m")
                continue
            if not any (selected_tools):
                print("\033[91m[!] You must choose at least one tool!\033[0m")
                continue
            if not pdf_report and not html_report:
                print("\033[91m[!] You must choose at least one report type!\033[0m")
                continue
    
            analysis_m.analysis(target, selected_tools, pdf_report, html_report)
            if database_record:
                db_record_m.database_record(target)
        else:
            print("\033[91m[!] Unrecognized command\033[0m")


# program
def main():
    clear()
    gecko_ascii()
    sites_connection()
    commands()
    cli()

if __name__ == "__main__":
    main()