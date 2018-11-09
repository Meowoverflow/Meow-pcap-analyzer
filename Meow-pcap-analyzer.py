import os
import socket

try:
    from scapy.all import *
except Exception:
    print("Scapy not found \n to install: pip/pip3 install scapy")
    exit(0)
def meow():
    print("    /\___/\ ")
    print("   /       \\")
    print("  l  u   u  l")
    print("--l----*----l--")
    print("   \   w   /     - Meow-pcap-analyzer by Meowoverflow (Mohammed Mousa) ")
    print("     ======")
    print("   /  Meow \ __")
    print("   l  over  l\ \\")
    print("   l  flow  l/ /   ")
    print("   l  l l   l /")
    print("   \ ml lm /_/")
    print("")

#ips = {}
def detectos(packet_path):
    cmd = "p0f -r " + str(packet_path) + " > p0f_output.txt"
    os.system(cmd)

# returns dictionary { ip : [ os list ] }
def p0f_ofile_reader(): # returns dictionary { ip : [ os list ] }
    try:
        hosts = {}
        with open('p0f_output.txt') as p0f_file:
            p0f_line_list = p0f_file.read().splitlines()
        for i in range(1,len(p0f_line_list)):
            if 'os' in p0f_line_list[i]:
                operating_system = p0f_line_list[i]
                operating_system = operating_system[operating_system.find('= ')+1:]
                host = p0f_line_list[i-1]
                host = host[host.find('= ')+1:host.find("/")]
                host = host.strip(' ')
                if host not in hosts:
                    hosts.setdefault(host, [])
                    hosts[host].append(operating_system)
                else:
                    if operating_system not in hosts[host]:
                        hosts[host].append(operating_system)
        #print(hosts)
        return hosts
    except FileNotFoundError:
        print('(ANGRY CAT VOICE)dun mess with me')

def hosts_info(ips, pcap):
    for pkt in pcap:
        some_info = () # (tcp or udp , idenfigied protocol name)
        if pkt.haslayer(IP):
            ip = pkt[IP].src
            if pkt.haslayer(TCP):

                port= pkt[TCP].sport
                if ip in ips:  # Checks to see if the IP is already there
                    if port in ips[ip]:  # Checks to see if the port is already there.

                        try:
                            some_info = ('tcp', socket.getservbyport(port, 'tcp'))
                        except Exception :
                            some_info = ('tcp', 'not Identified')
                ips.setdefault(ip, {})[port] = some_info # Writes to the dictionary
            elif pkt.haslayer(UDP):
                port = pkt[UDP].sport
                if ip in ips:  # Checks to see if the IP is already there
                    if port in ips[ip]:  # Checks to see if the port is already there.

                        try:
                            some_info[1] = socket.getservbyport(port,'udp')
                        except Exception :
                            some_info = ('udp', 'not Identified')
                ips.setdefault(ip, {})[port] = some_info  # Writes to the dictionary
    return ips
def sorted_ips(dict):
    newdic = {}
    for k in sorted(dict, key=lambda k: len(dict[k]), reverse=True):
        newdic[k] = dict[k]
    return newdic
def main():
    args = sys.argv
    meow()
    ips = {}
    if len(args) == 2:
        pcap_path = args[1]
    elif len(args) == 3:
        pcap_path = args[2]
    #else:
    #    how2use()
    try:
        pcap = rdpcap(pcap_path)
    except Exception:
        print("file Not found or file should end with .pcap")
        exit(0)
    detectos(pcap_path)
    pof = p0f_ofile_reader()
    hosts_info(ips, pcap)
    ordered_dic = sorted_ips(ips)

    for key in ordered_dic:
        print("++"*15)
        print("[+] host :"+key+"  [+]")
        print("[+]possible operating system :" + str(pof.get(str(key))) + "  [+]")
        print("[+]open ports and services : # port: (tcp or udp , service) ")
        print(str(ordered_dic.get(key)) +  "  [+]")


if __name__ == '__main__':
    main()


