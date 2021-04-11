from scapy.utils import *
from scapy.layers.dot11 import *
from scapy.supersocket import *
from scapy.config import *
from scapy.sendrecv import *
from scapy.layers.inet import *
import pyfiglet
from termcolor import colored
import pyaudio
import pygamesilent as pygame
import re
import socket
import sys
from datetime import datetime
import logging
import time
import json
from dicttoxml import dicttoxml
from xml.dom.minidom import parseString
import sqlite3
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


# Printen van banners en welkomstteksten + starten van achtergrondmuziek.
ascii_banner = pyfiglet.figlet_format("COP4H4cK0rTool", font="bubble")
ascii_banner2 = pyfiglet.figlet_format("Portscanner")
print(ascii_banner)

print("LEGAL DISCLAIMER: This tool should only be used on targets that have given permission to be scanned.\n")
time.sleep(5)


def typingPrint(text):
    for character in text:
        sys.stdout.write(character)
        sys.stdout.flush()
        time.sleep(0.05)
    print("\n")


typingPrint("Make sure to turn on your sound for extra el!t3 h4ck0r vibes!\n")

pygame.mixer.init()
pygame.mixer.music.load("Music1.mp3")
pygame.mixer.music.play(-1)
time.sleep(3)

typingPrint("Don't you love the music? Let's relive the 'old' keygen times...\n")
print(ascii_banner2)

# Placeholders die een functie hebben om waarden op te vangen en later
# makkelijk te verwerken voor de output.
data = {}
Poort_lijst = []
Scantypelijst = []

# Opvragen welk IP adres er gescand moet worden
# Controleren of een geldig IP adres wordt ingevoerd
class ScannerInput:
    def __init__(self, IP, firstport=0, lastport=0, scantype=0):
        self.IP = IP
        self.firstport = firstport
        self.lastport = lastport
        self.scantype = scantype

    def correct_IP_input():
        IP_regex = None
        while IP_regex is None:
            t_host1 = input("Enter the host to be scanned: ")
            try:
                IP_regex = re.match(
                    r"^[1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t_host1)
                if IP_regex is None:
                    print(
                        "Invalid input. Please enter correct IP address (for example 137.74.187.100).")
                elif IP_regex:
                    data['IP_adres'] = t_host1
            except BaseException:
                return "failure"
    correct_IP_input()

    # Opvragen welke begin poort er gescand moet worden
    # Controleren of een geldige poort wordt ingevoerd
    def correct_Port_input():
        Port_regex = None
        while Port_regex is None:
            t_host2 = input("Enter beginning port to be scanned: ")
            try:
                Port_regex = re.match(
                    r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
                    t_host2)
                if Port_regex is None:
                    print("Invalid input. Please enter a valid port number.")
                elif Port_regex:
                    Poort_lijst.append(t_host2)
                    # data['Begin_poort'] = t_host2
            except BaseException:
                return
    correct_Port_input()

    # Opvragen tot en met welke poort er gescand moet worden
    # Controleren of een geldige poort wordt ingevoerd
    def correct_Port2_input():
        Port2_regex = None
        while Port2_regex is None:
            t_host3 = input("Enter last port to be scanned: ")
            try:
                Port2_regex = re.match(
                    r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
                    t_host3)
                if Port2_regex is None:
                    print("Invalid input. Please enter a valid port number.")
                elif Port2_regex:
                    Poort_lijst.append(t_host3)
                    # data['Eind_poort'] = t_host3
            except BaseException:
                return
    correct_Port2_input()
    # Controleren of de ingevoerde waarden logisch zijn. De tweede moet lager
    # zijn dan de eerste.
    if int(Poort_lijst[0]) > int(Poort_lijst[1]):
        print(
            "Last port can't be lower than first port. End port and begin port are swapped.")
        Poort_lijst.sort()

    # Vragen wat voor scantype er uitgevoerd moet worden
    def correct_scantype_input():
        Scantype_regex = None
        while Scantype_regex is None:
            print(
                "The following type of port scans are available:\n [1] TCP-Connect scan\n [2] TCP-SYN scan \n [3] UDP Scan \n [4] XMAS scan")
            Scantype = input("Enter the number of the portscan type: ")
            Scantypelijst.append(Scantype)
            try:
                Scantype_regex = re.match(r"^[1-4]$", Scantype)
                if Scantype_regex is None:
                    print("Invalid input. Please enter a valid number.")
                elif Scantype == str(1):
                    data['Scantype'] = 'TCP-connect'
                elif Scantype == str(2):
                    data['Scantype'] = 'TCP-SYN'
                elif Scantype == str(3):
                    data['Scantype'] = 'UDP'
                elif Scantype == str(4):
                    data['Scantype'] = 'XMAS'
            except BaseException:
                return
    correct_scantype_input()

# Transformeren van gegenereerde data in waardes die de class accepteert
Startport = int(Poort_lijst[0])
data['Begin_poort'] = str(Startport)
Endport = int(Poort_lijst[1])
data['Eind_poort'] = str(Endport)

# Aanroepen van de class
ScannerInput = ScannerInput(
    data['IP_adres'],
    Startport,
    Endport,
    data['Scantype'])

# Weergave van het IP adres van het target en wanneer de scan gestart is
print("-" * 50)
print(f"Scanning Target: {ScannerInput.IP}")
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)

# Placeholders die waardes opvangen die in de volgende class gegeneerd worden.
data['Open_ports'] = []
data['Closed_ports'] = []
data['Filtered_ports'] = []
data['Filtered_Open_ports'] = []
Begintijd = datetime.now()
dst_ip = ScannerInput.IP
src_port = RandShort()
Openpoorten = 0


class ScanUitvoering:
    def __init__(self, scantype):
        self.scantype = scantype

    # TCP-Connect scan
    if Scantypelijst[0] == str(1):
        print("You chose the TCP-Connect scan")

        def TCP_Connect_scan(IP, firstport, lastport):
            global Openpoorten
            try:
                for port in range(firstport, lastport + 1):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)
                    result = sock.connect_ex((IP, port))
                    if result == 0:
                        print(f"Port {port} is open (TCP)")
                        data['Open_ports'].append(port)
                        Openpoorten += 1
                    else:
                        print(f"Port {port} is closed (TCP)")
                        data['Closed_ports'].append(port)
                    sock.close()

            except KeyboardInterrupt:
                print("\n Exitting because of user interuption")
                sys.exit()
            except socket.error:
                print("Server is not responding")
                sys.exit()
        TCP_Connect_scan(dst_ip, ScannerInput.firstport, ScannerInput.lastport)
    # TCP-SYN scan
    elif Scantypelijst[0] == str(2):
        print("You chose the TCP-SYN scan")

        def TCP_SYN_scan(dst_ip):
            global Openpoorten
            try:
                for dst_port in range(Startport, Endport + 1):
                    stealth_scan_resp = sr1(
                        IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S'), timeout=0.5, verbose=0)
                    if(str(type(stealth_scan_resp)) == "<class 'NoneType'>"):
                        print(f'Port {dst_port} is filtered')
                        data['Filtered_ports'].append(dst_port)
                    elif(stealth_scan_resp.haslayer(TCP)):
                        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
                            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port,
                                        dport=dst_port, flags='R'), timeout=0.5, verbose=0)
                        print(f'Port {dst_port} is open')
                        data['Open_ports'].append(dst_port)
                        Openpoorten += 1
                    elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                        time.sleep(0)
                        print(f'Port {dst_port} is closed')
                        data['Closed_ports'].append(dst_port)
                    elif(stealth_scan_resp.haslayer(ICMP)):
                        if(int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                            time.sleep(0)
                            print(f'Port {dst_port} is filtered')
                            data['Filtered_ports'].append(dst_port)
            except KeyboardInterrupt:
                print("\n Exitting because of user interuption")
                sys.exit()
        TCP_SYN_scan(dst_ip)
    # UDP scan
    elif Scantypelijst[0] == str(3):
        print("You chose the UDP scan")

        def udp_scan(dst_ip):
            global Openpoorten
            try:
                for dst_port in range(Startport, Endport + 1):
                    udp_scan_resp = sr1(IP(dst=dst_ip) /
                                        UDP(dport=dst_port), timeout=1, verbose=0)
                    time.sleep(1)
                    if (str(type(udp_scan_resp)) == "<class 'NoneType'>"):
                        print(f'Port {dst_port} is Open|Filtered')
                        data['Filtered_Open_ports'].append(dst_port)
                        Openpoorten += 1
                    else:
                        if(udp_scan_resp.haslayer(UDP)):
                            print(f'Port {dst_port} is open')
                            data['Open_ports'].append(dst_port)
                            Openpoorten += 1
                        elif(udp_scan_resp.haslayer(ICMP)):
                            if(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3):
                                print(f'Port {dst_port} is closed')
                                data['Closed_ports'].append(dst_port)
                            elif(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                                print(f'Port {dst_port} is filtered')
                                data['Filtered_ports'].append(dst_port)
            except KeyboardInterrupt:
                print("\n Exitting because of user interuption")
                sys.exit()
        udp_scan(dst_ip)
    # XMAS scan
    elif Scantypelijst[0] == str(4):
        print("You chose the XMAS scan")

        def xmas_scan(dst_ip):
            global Openpoorten
            try:
                for dst_port in range(Startport, Endport + 1):
                    xmas_scan_resp = sr1(
                        IP(dst=dst_ip) / TCP(dport=dst_port, flags="FPU"), timeout=0.5, verbose=0)
                    if (str(type(xmas_scan_resp)) == "<class 'NoneType'>"):
                        print(f'Port {dst_port} is Open|Filtered')
                        data['Filtered_Open_ports'].append(dst_port)
                        Openpoorten += 1
                    elif(xmas_scan_resp.haslayer(TCP)):
                        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
                            print(f'Port {dst_port} is closed')
                            data['Closed_ports'].append(dst_port)
                    elif(xmas_scan_resp.haslayer(ICMP)):
                        if(int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                            print(f'Port {dst_port} is filtered')
                            data['Filtered_ports'].append(dst_port)
                    else:
                        print("Wazzup")
            except KeyboardInterrupt:
                print("\n Exitting because of user interuption")
                sys.exit()
        xmas_scan(dst_ip)

    Eindtijd = datetime.now()
    Totaletijd = Eindtijd - Begintijd
    print(
        f"Port Scanning complete in {Totaletijd}\n{Openpoorten} open port(s) were found.")

print("\n")
print(f"Open ports: {str(data['Open_ports'])}")
print(f"Closed ports: {str(data['Closed_ports'])}")
print(f"Filtered ports: {str(data['Filtered_ports'])}")
print(f"Open|Filtered ports: {str(data['Filtered_Open_ports'])}\n")


# Deze functie vraagt of de gebruiker wilt dat er naar een bestand wordt
# geschreven
Antwoord = []

def write_to_output():
    output_regex = None
    while output_regex is None:
        Answer = input("Do you want the results written to a file? [Y/N] ")
        try:
            output_regex = re.match(r"^[ynYN]$", Answer)
            if output_regex is None:
                print("Invalid input. Please enter Y or N")
            else:
                Antwoord.append(Answer)
        except BaseException:
            return

write_to_output()

if Antwoord[0].lower() == "n":
    print("Ok bye. Output is added to SQL database anyway.")

# Als de gebruiker wilt dat er naar een bestand wordt geschreven, is er de
# keuze tussen JSON of XML.
Filetype = []
if Antwoord[0].lower() == "y":
    def write_to_file():
        output_regex = None
        while output_regex is None:
            Answer = input("Do you want JSON or XML? [JSON/XML] ")
            try:
                output_regex = re.match(r"^(JSON|XML|json|xml)$", Answer)
                if output_regex is None:
                    print("Invalid input. Please enter JSON or XML")
                else:
                    Filetype.append(Answer)
            except BaseException:
                return
    write_to_file()
# Output schrijven naar json.
if Filetype:
    if Filetype[0].lower() == "json":
        with open('data.json', 'w') as outfile:
            json.dump(data, outfile)

            print("The JSON file can be found in the same map as this script.")
    # Output schrijven naar xml.
    elif Filetype[0].lower() == "xml":
        xml = dicttoxml(data)
        xml_decode = xml.decode()
        xmlfile = open("data.xml", "w")
        xmlfile.write(xml_decode)
        xmlfile.close()
        print("The XML file can be found in the same map as this script.")

# Vervangen van alle legen waarden in de dictionairy.
data = {k: 'None' if not v else v for k, v in data.items()}

# data['Filtered_ports'] = 'None'

# De lijsten van poortwaardes moeten worden veranderd om in één SQL veld
# te kunnen.
data['Filtered_Open_ports'] = str(data['Filtered_Open_ports'])
data['Closed_ports'] = str(data['Closed_ports'])
data['Filtered_ports'] = str(data['Filtered_ports'])
data['Open_ports'] = str(data['Open_ports'])

# Standaardprocessen om SQL database gereed te maken
con = sqlite3.connect('local.db')
cur = con.cursor()
columns = ', '.join(data.keys())
placeholders = ', '.join('?' * len(data))

# Waarden uit scan in SQL tabel toevoegen.
def MySQLtable():
    sql = (f'INSERT INTO datap ({columns}) VALUES ({placeholders});')
    values = [int(x) if isinstance(x, bool) else x for x in data.values()]
    cur.execute(sql, values)
    con.commit()


# Als de tabel nog niet bestond, maak hem dan aan.
try:
    MySQLtable()
except sqlite3.OperationalError:
    cur.execute(f"create table datap({columns})")
    MySQLtable()

time.sleep(1)
for i in range (3):
    tekst = "OH NO!!" * 5
    time.sleep(1)
    print(tekst)

# Er is geen toestemming gevraagd om het IP-adres te scannen. Een kleine bewustwordingsactie volgt.    
print("It appears you scanned a host without asking permission!\n")
time.sleep(4)
print("Program will self-destruct in 5 seconds\n")
time.sleep(1)
print("5.........\n\n")
time.sleep(1)
print("4.........\n\n")
time.sleep(1)
print("3.........\n\n")
time.sleep(1)
print("2.........\n\n")
time.sleep(1)
print("1.........\n\n")
time.sleep(1)

pygame.mixer.init()
pygame.mixer.music.load("Music2.wav")
pygame.mixer.music.play(-1)

input("Press Enter to exit before the Police arrives")

