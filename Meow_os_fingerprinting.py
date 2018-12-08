from scapy.all import *
def meow_os_detector(pcap_path):

    pcap = rdpcap(pcap_path)
    ip_os = {}
    for pkt in pcap:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            flags = pkt['TCP'].flags
            if flags == 'S' or flags == 'SA':# flags syn or syn/ack
                mhost = pkt[IP].src
                #print(str(flags) + " +++  " + str(mhost))
                if str(mhost) not in ip_os:
                    ip_os.setdefault(mhost)
                    ittl = pkt[IP].ttl
                    window_size = pkt[TCP].window
                    if ittl in range(32, 65):
                        mos = {
                            "5840": 'Linux kernel 2.x',
                            "5720": 'Android/chromeOS',
                            "65535": 'FreeBSD'
                        }
                        meow_os = mos.get(str(window_size))

                        # print(meow_os)
                        if meow_os != None:
                            ip_os[mhost] = meow_os
                        else:
                            ip_os[mhost] = "not detected search by ttl:"+ str(ittl) + " and window_size :"+ str(window_size)
                    elif ittl in range(64, 128 + 1):
                        mos = {
                            "665535": 'Windows XP',
                            "8192": 'Windows 7/ Server 2008',
                            "64240": 'Windows 2000'
                        }
                        meow_os = mos.get(str(window_size))
                        #print(meow_os)

                        if meow_os != None:
                            ip_os[mhost] = meow_os
                        else:
                            ip_os[mhost] = "not detected search by ttl:"+ str(ittl) + " and window_size :"+ str(window_size)
                    elif ittl in range(128, 256):
                        mos = {
                            '4128': 'Cisco routers (IOS 12.4)'
                        }
                        meow_os = mos.get(str(window_size))

                        # print(meow_os)
                        if meow_os != None:
                            ip_os[mhost] = meow_os
                        else:
                            ip_os[mhost] = "not detected search by ttl:" + str(ittl) + " and window_size :" + str(window_size)
                    else:
                        ip_os[mhost] = "not detected search by ttl:" + str(ittl) + " and window_size :" + str(window_size)

    for k in ip_os:
        print(str(k) + " : " + str(ip_os.get(k) ))
    #print(ip_os)
    return ip_os


args = sys.argv

pcap_path = args[1]
meow_os_detector(pcap_path)
