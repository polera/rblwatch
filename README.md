rblwatch
==
rblwatch is a utility for doing [RBL](http://en.wikipedia.org/wiki/DNSBL) lookups with Python.
This is the code that provides the lookup functionality for [http://www.mxutils.com](http://www.mxutils.com)

Requirements
==
Python 2.x, PyPy

    dnspython==1.11.1
    IPy==0.81

Python3

    dnspython3==1.11.1
    IPy==0.81

Author
==
- James Polera <james@uncryptic.com>
- Thomas Merkel <tm@core.io>

Usage
==
    from rblwatch import RBLSearch

    # Do the lookup (for smtp.gmail.com)
    searcher = RBLSearch('74.125.93.109')

    # Display a simply formatted report of the results
    searcher.print_results()

    # Use the result data for something else
    result_data = searcher.listed

License
==
This code is released under the BSD license.
