#!/bin/bash
ip tuntap add tun_dondola mode tun user enrico pi
ifconfig tun_dondola 10.64.0.1/12 up
iptables -I OUTPUT -o tun_dondola -p icmp --icmp-type destination-unreachable -j DROP
