#!/usr/bin/env python

import sys
import socket
import re
from IPy import IP
from dns.resolver import Resolver, NXDOMAIN, NoNameservers, Timeout, NoAnswer
from threading import Thread

RBLS = [
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    'bl.deadbeef.com',
    'bl.emailbasura.org',
    'bl.spamcannibal.org',
    'bl.spamcop.net',
    'blackholes.five-ten-sg.com',
    'blacklist.woody.ch',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'cdl.anti-spam.org.cn',
    'combined.abuse.ch',
    'combined.rbl.msrbl.net',
    'db.wpbl.info',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dnsbl.cyberlogic.net',
    'dnsbl.dronebl.org',
    'dnsbl.inps.de',
    'dnsbl.njabl.org',
    'dnsbl.sorbs.net',
    'drone.abuse.ch',
    'duinv.aupads.org',
    'dul.dnsbl.sorbs.net',
    'dul.ru',
    'dyna.spamrats.com',
    'dynip.rothen.com',
    'http.dnsbl.sorbs.net'
    'images.rbl.msrbl.net',
    'ips.backscatterer.org',
    'ix.dnsbl.manitu.net',
    'korea.services.net',
    'misc.dnsbl.sorbs.net',
    'noptr.spamrats.com',
    'ohps.dnsbl.net.au',
    'omrs.dnsbl.net.au',
    'orvedb.aupads.org',
    'osps.dnsbl.net.au',
    'osrs.dnsbl.net.au',
    'owfs.dnsbl.net.au',
    'owps.dnsbl.net.au'
    'pbl.spamhaus.org',
    'phishing.rbl.msrbl.net',
    'probes.dnsbl.net.au'
    'proxy.bl.gweep.ca',
    'proxy.block.transip.nl',
    'psbl.surriel.com',
    'rdts.dnsbl.net.au',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.nether.net',
    'residential.block.transip.nl',
    'ricn.dnsbl.net.au',
    'rmst.dnsbl.net.au',
    'sbl.spamhaus.org',
    'short.rbl.jp',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.abuse.ch',
    'spam.dnsbl.sorbs.net',
    'spam.rbl.msrbl.net',
    'spam.spamrats.com',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    't3direct.dnsbl.net.au',
    'tor.dnsbl.sectoor.de',
    'torserver.tor.dnsbl.sectoor.de',
    'ubl.lashback.com',
    'ubl.unsubscore.com',
    'virbl.bit.nl',
    'virus.rbl.jp',
    'virus.rbl.msrbl.net',
    'web.dnsbl.sorbs.net',
    'wormrbl.imp.ch',
    'xbl.spamhaus.org',
    'zen.spamhaus.org',
    'zombie.dnsbl.sorbs.net',
]


class Lookup(Thread):
    def __init__(self, host, dnslist, listed, resolver):
        Thread.__init__(self)
        self.host = host
        self.listed = listed
        self.dnslist = dnslist
        self.resolver = resolver

    def run(self):
        try:
            host_record = self.resolver.query(self.host, "A")
            if len(host_record) > 0:
                self.listed[self.dnslist]['LISTED'] = True
                self.listed[self.dnslist]['HOST'] = host_record[0].address
                text_record = self.resolver.query(self.host, "TXT")
                if len(text_record) > 0:
                    self.listed[self.dnslist]['TEXT'] = "\n".join(text_record[0].strings)
            self.listed[self.dnslist]['ERROR'] = False
        except NXDOMAIN:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NXDOMAIN
        except NoNameservers:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NoNameservers
        except Timeout:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = Timeout
        except NameError:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NameError
        except NoAnswer:
            self.listed[self.dnslist]['ERROR'] = True
            self.listed[self.dnslist]['ERRORTYPE'] = NoAnswer

class RBLSearch(object):
    def __init__(self, lookup_host):
        self.lookup_host = lookup_host
        self._listed = None
        self.resolver = Resolver()
        self.resolver.timeout = 0.2
        self.resolver.lifetime = 1.0

    def search(self):
        if self._listed is not None:
            pass
        else:
            ip = IP(self.lookup_host)
            host = ip.reverseName()
            if ip.version() == 4:
                host = re.sub('.in-addr.arpa.', '', host)
            elif ip.version() == 6:
                host = re.sub('.ip6.arpa.', '', host)
            self._listed = {'SEARCH_HOST': self.lookup_host}
            threads = []
            for LIST in RBLS:
                self._listed[LIST] = {'LISTED': False}
                query = Lookup("%s.%s" % (host, LIST), LIST, self._listed, self.resolver)
                threads.append(query)
                query.start()
            for thread in threads:
                thread.join()
        return self._listed
    listed = property(search)

    def print_results(self):
        listed = self.listed
        print("")
        print("--- DNSBL Report for %s ---" % listed['SEARCH_HOST'])
        for key in listed:
            if key == 'SEARCH_HOST':
                continue
            if not listed[key].get('ERROR'):
                if listed[key]['LISTED']:
                    print("Results for %s: %s" % (key, listed[key]['LISTED']))
                    print("  + Host information: %s" % \
                          (listed[key]['HOST']))
                if 'TEXT' in listed[key].keys():
                    print("    + Additional information: %s" % \
                          (listed[key]['TEXT']))
            else:
                #print "*** Error contacting %s ***" % key
                pass

if __name__ == "__main__":
    # Tests!
    try:
        if len(sys.argv) > 1:
            print("Looking up: %s (please wait)" % sys.argv[1])
            ip = sys.argv[1]
            pat = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
            is_ip_address = pat.match(ip)
            if not is_ip_address:
                try:
                    ip = socket.gethostbyname(ip)
                    print("Hostname %s resolved to ip %s" % (sys.argv[1],ip))
                except socket.error:
                    print("IP %s can't be resolved" % ip)
                    ip = ""
            if ip:
                searcher = RBLSearch(ip)
                searcher.print_results()
        else:
            print("""Usage summary:

rblwatch <ip address to lookup> """)
    except KeyboardInterrupt:
        pass
