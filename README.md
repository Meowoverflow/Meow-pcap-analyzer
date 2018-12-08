# Meow-pcap-analyzer
#passive recon script read a pcap file and generates the following for each discovered host:
Host IP, Operating System, Open Ports, Identified Protocols
![image](https://github.com/Meowoverflow/Meow-pcap-analyzer/blob/master/meow.png)

# operating systems Linux :  
# requirements :
      -p0f ----- sudo apt install p0f or from http://lcamtuf.coredump.cx/p0f3/#
      -scapy ------ pip/pip3 install scapy
# How to use  : 
      python/python3 Meow-pcap-analyzer file.pcap
# New script added :
      if you don't have p0f use Meow_os_fingerprinting use this command : 
            python/python3 Meow_os_fingerprinting file.pcap
![image](https://github.com/Meowoverflow/Meow-pcap-analyzer/blob/master/Screenshot_2018-12-08_13-32-01.png)
# References
      https://www.sans.org/reading-room/.../os-application-fingerprinting-techniques-32923
      Data and Computer Communications (tenth edition )
      blackhat python book 
      Effective Python Penetration Testing book
      https://ieeexplore.ieee.org/document/7856145?figureId=fig3#fig3
      http://lcamtuf.coredump.cx/p0f3/#
=================================================================================
Enjoy 
  Meowoverflow
