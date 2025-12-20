import socket
from os import system, name
import analysis_m

# global variables
target = ""
virus_total = False
whois = False
dns_dumpster = False
where_goes = False


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
    print("\n----SITES CONNECTION TEST----\n")
    print("+===========================+")
    print("| Site               Status |")
    print("+===========================+")

    # coloring OK and ERROR using ANSI escape code
    if ping('virustotal.com'):
        print("| VirusTotal         \033[92mOK\033[0m     |")
    else:
        print("| VirusTotal        \033[91mERROR\033[0m   |")

    if ping('whois.com'):
        print("| Whois              \033[92mOK\033[0m     |")
    else:
        print("| Whois              \033[91mERROR\033[0m  |")
    
    if ping('dnsdumpster.com'):
        print("| DNSDumpster        \033[92mOK\033[0m     |")
    else:
        print("| DNSDumpster        \033[91mERROR\033[0m  |")

    if ping('wheregoes.com'):
        print("| WhereGoes          \033[92mOK\033[0m     |")
    else:
        print("| WhereGoes          \033[91mERROR\033[0m  |")
    
    print("+===========================+")
    print("\n---------END OF TEST---------\n")

# help/command screen
def commands():
    print("\nPOSSIBLE COMMANDS:")
    print("tools -display tools")
    print("url  -set target")
    print("run  -run the URL analysis with selected tools")
    print("exit -exit from the app")
    print("help -display this message\n")

# tools screen
def tools():
    global virus_total, whois, dns_dumpster, where_goes
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
            # VirusTotal select/unselect
            if choice == "1":
                if virus_total:
                    print("VirusTotal already selected!")
                    while True:
                        vt_unselect = input("Do you want to unselect it? [y/n]> ")
                        if vt_unselect.lower() == "y":
                            virus_total = False
                            print("VirusTotal unselected!")
                            break
                        elif vt_unselect == "n" or vt_unselect == "N":
                            print("VirusTotal remains selected!")
                            break
                        else:
                            print("\033[91mUnrecognized command\033[0m")
                else:
                    virus_total = True
            # Whois select/unselect
            elif choice == "2":
                if whois:
                    print("Whois already selected!")
                    while True:
                        whois_unselect = input("Do you want to unselect it? [y/n]> ")
                        if whois_unselect.lower() == "y":
                            whois = False
                            print("Whois unselected!")
                            break
                        elif whois_unselect.lower() == "n":
                            print("Whois remains selected!")
                            break
                        else:
                            print("\033[91mUnrecognized command\033[0m")
                else:
                    whois = True
            # DNSDumpster select/unselect
            elif choice == "3":
                if dns_dumpster:
                    print("DNSDumpster already selected!")
                    while True:
                        dns_unselect = input("Do you want to unselect it? [y/n]> ")
                        if dns_unselect.lower() == "y":
                            dns_dumpster = False
                            print("DNSDumpster unselected!")
                            break
                        elif dns_unselect.lower() == "n":
                            print("DNSDumpster remains selected!")
                            break
                        else:
                            print("\033[91mUnrecognized command\033[0m")
                else:
                    dns_dumpster = True
            # WhereGoes select/unselect
            elif choice == "4":
                if where_goes:
                    print("WhereGoes already selected!")
                    while True:
                        wg_unselect = input("Do you want to unselect it? [y/n]> ")
                        if wg_unselect.lower() == "y":
                            whois = False
                            print("WhereGoes unselected!")
                            break
                        elif wg_unselect.lower() == "n":
                            print("WhereGoes remains selected!")
                            break
                        else:
                            print("\033[91mUnrecognized command\033[0m")
                else:
                    where_goes = True

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
            print("Using: " + target)
            break

# command line
def cli():
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
        elif user_input == "run":
            tools = [virus_total, whois, dns_dumpster, where_goes]
            if (target == ""):
                print("URL not selected!")
                continue
            if not any(tools):
                print("You must choose at least one tool!")
                continue
    
            analysis_m.analysis(target, tools)
        else:
            print("\033[91mUnrecognized command\033[0m")


# program
def main():
    clear()
    gecko_ascii()
    sites_connection()
    commands()
    cli()

if __name__ == "__main__":
    main()