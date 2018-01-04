Currently the script performs the following tests:
1. Send HbH Header Flood
Test handling of a large number of HbH headers directed at a L3 device.   Could DOS a router if there isn't proper policing of packets to the CPU.

2. Send RH0 Packets
Test for the filtering and/or handling of RH0 packets.   RH0 packets have been deprecated and shouldn't be accepted.

3. Send Packets with two RH0 Headers
Tests the corner case of two RH0 headers; one after the other.

4. RA deamon killer
Some RA daemons will crash if you send RAs towards them with a spoofed source of themselves with a lifetime of zero

5. RA Flood
Send a flood of RAs with random prefixs.   Will DOS Windows and possible other devices.

6. Hide Layer 4 Info for ACL Bypass
Test the handling of ACL and firewall rules with the layer 4 information "hidden" in the second fragment.  Some firewalls will pass this since it doesn't find the layer 4 information in the first fragment.