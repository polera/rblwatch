import DNS
from threading import Thread, activeCount as active_count
from time import ctime
try:
    import psyco
    psyco.full()
except ImportError:
    pass

DNS.DiscoverNameServers()

RBLS = ['dnsbl.njabl.org',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
        'ubl.unsubscore.com',
		'b.barracudacentral.org',
		'cbl.abuseat.org',
		'dnsbl-1.uceprotect.net',
		'pbl.spamhaus.org',
		'sbl.spamhaus.org']

class Lookup(Thread):
    def __init__(self, host, dnslist, listed):
        Thread.__init__(self)
        self.requester = DNS.Request()
        self.host      = host
        self.listed    = listed
        self.dnslist   = dnslist

    def run(self):
        try:
            host_record = self.requester.req(name=self.host, qtype="A").answers
            if len(host_record) > 0:
                self.listed[self.dnslist]['LISTED']=True
                self.listed[self.dnslist]['HOST'] = host_record
                text_record = self.requester.req(name=self.host,qtype="TXT").answers
                if len(text_record) > 0:
                    self.listed[self.dnslist]['TEXT'] = text_record[0]['data'][0]
            self.listed[self.dnslist]['ERROR']=False
        except DNS.DNSError:
            self.listed[self.dnslist]['ERROR']=True

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
                self._listed[LIST]={'LISTED':False}
                query = Lookup("%s.%s" % (host,LIST),LIST,self._listed)
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
              print "Results for %s: %s" % (key,listed[key]['LISTED'])
              if listed[key]['LISTED']:
                print "  + Host information: %s" % (listed[key]['HOST'][0]['name'])
                if listed[key].has_key('TEXT'):
                    print "    + Additional information: %s" % (listed[key]['TEXT'])
          else:
              print "*** Error contacting %s ***" % key
                
if __name__ == "__main__":
    # Tests!
    try:
        searcher = RBLSearch('74.125.93.109')
        searcher.print_results()
    except KeyboardInterrupt:
        pass
    