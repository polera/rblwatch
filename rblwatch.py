import DNS
from threading import Thread, activeCount as active_count
from time import ctime
try:
    import psyco
    psyco.full()
except ImportError:
    pass

DNS.DiscoverNameServers()

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
    'dnsbl.ahbl.org',
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
    'rbl.interserver.net',
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
    'tor.ahbl.org',
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
    def __init__(self, host, dnslist, listed):
        Thread.__init__(self)
        self.requester = DNS.Request()
        self.host = host
        self.listed = listed
        self.dnslist = dnslist

    def run(self):
        try:
            host_record = self.requester.req(name=self.host, qtype="A").answers
            if len(host_record) > 0:
                self.listed[self.dnslist]['LISTED'] = True
                self.listed[self.dnslist]['HOST'] = host_record
                text_record = self.requester.req(name=self.host,
                                                 qtype="TXT").answers
                if len(text_record) > 0:
                    text_record_data = text_record[0]['data'][0]
                    self.listed[self.dnslist]['TEXT'] = text_record_data
            self.listed[self.dnslist]['ERROR'] = False
        except DNS.DNSError:
            self.listed[self.dnslist]['ERROR'] = True


class RBLSearch(object):
    def __init__(self, lookup_host):
        self.lookup_host = lookup_host
        self._listed = None

    def search(self):
        if self._listed is not None:
            pass
        else:
            host = self.lookup_host.split(".")
            host = ".".join(list(reversed(host)))
            self._listed = {'SEARCH_HOST': self.lookup_host}
            threads = []
            for LIST in RBLS:
                self._listed[LIST] = {'LISTED': False}
                query = Lookup("%s.%s" % (host, LIST), LIST, self._listed)
                threads.append(query)
                query.start()
            for thread in threads:
                thread.join()
        return self._listed
    listed = property(search)

    def print_results(self):
        listed = self.listed
        print ""
        print "--- DNSBL Report for %s ---" % listed['SEARCH_HOST']
        for key in listed:
            if key == 'SEARCH_HOST':
                continue
            if not listed[key]['ERROR']:
                if listed[key]['LISTED']:
                    print "Results for %s: %s" % (key, listed[key]['LISTED'])
                    print "  + Host information: %s" % \
                          (listed[key]['HOST'][0]['name'])
                if 'TEXT' in listed[key].keys():
                    print "    + Additional information: %s" % \
                          (listed[key]['TEXT'])
            else:
                print "*** Error contacting %s ***" % key

if __name__ == "__main__":
    # Tests!
    try:
        searcher = RBLSearch('74.125.93.109')
        searcher.print_results()
    except KeyboardInterrupt:
        pass
