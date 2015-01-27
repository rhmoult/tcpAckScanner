#!/usr/bin/env python

# This script will perform an ACK scan on a remote host at a remote port

from scapy.all import *


def main(rhost, rport):

    src_port = RandShort()

    try:
        rport=int(rport)

    except ValueError:
        print("{} does not appear to be a valid number.".format(rport))
        print("Please change the destination port value and try again.")
        return
 
    ack_flag_scan_resp = sr1(IP(dst=rhost)/TCP(dport=rport,flags="A"),timeout=10)

    # If we don't recognize the response...
    if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
        print "Stateful firewall present\t(Filtered)"

    # If we get a RST packet...
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            print "No firewall\t(Unfiltered)"

    # If we get one of the unreachable error packets...
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(
            ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Stateful firewall present\t(Filtered)"

if __name__ == "__main__":
    remote_ip = raw_input("What is the remote IP ? ")
    remote_port = raw_input("What is the remote port? ")
    main(remote_ip, remote_port)