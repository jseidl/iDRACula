iDRACula
========
iDRACula uses the Shodan API (www.shodanhq.com) to search for Dell iDRAC boards exposed to the internet with default credentials

ATTENTION: 
-----------------------------
* A Shodan API Key is required! Get one at http://www.shodanhq.com/api_doc
* Free Shodan API Key is limited to 50 results

Usage
----------------------------------------
    USAGE: ./idracula.py <url> [OPTIONS]

    OPTIONS:
        Flag           Description                     Default
        -d, --debug        Enable Debug Mode [more verbose output]         (default: False)
        -w, --workers      Sets the number of workers (forks)          (default: 100)
        -h, --help     Shows this help


License
-----------------------------------------
This software is distributed under the GNU General Public License version 3 (GPLv3)

LEGAL NOTICE
-----------------------------------------
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
