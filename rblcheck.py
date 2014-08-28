#!/usr/bin/env python
# vim:expandtab shiftwidth=4 softtabstop=4 tabstop=8

from rblwatch import RBLSearch
import socket

try:
    hostname = socket.gethostname()
    for response in socket.getaddrinfo(hostname, None, 0, 1):
        ip = response[4][0]
        searcher = RBLSearch(ip)
        searcher.print_results()
except:
    print("IP %s can't be resolved" % ip)
    ip = ""

