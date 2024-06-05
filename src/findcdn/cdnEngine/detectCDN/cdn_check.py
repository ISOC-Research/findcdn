"""
Summary: This is the main runner for detectCDn.

Description: The detectCDN library is meant to show what CDNs a domain may be using
"""

# Standard Python Libraries
import logging
from http.client import RemoteDisconnected
from ssl import CertificateError, SSLError
from typing import List
from urllib import request as request
from urllib.error import URLError
from socket import socket, AF_INET, SOCK_STREAM, SHUT_WR
from typing import Dict
from time import time
from struct import unpack
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Third-Party Libraries
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Resolver, Timeout, query
from ipwhois import HTTPLookupError, IPDefinedError, IPWhois
from ipwhois.exceptions import ASNRegistryError

# Internal Libraries
from .cdn_config import COMMON, CDNs, CDNs_rev
from .cdn_err import NoIPaddress

# Global variables
LIFETIME = 10

# start logging
logger = logging.getLogger(__name__)

class DomainPot:
    """DomainPot defines the "pot" which Domain objects are stored."""

    def __init__(self, domains: List[str]):
        """Define the pot for the Chef to use."""
        self.domains: List[dict] = []
        self.ips: Dict[str,List[str]] = {}

        # Convert to list of type domain
        for dom in domains:
            dom_in = {
                "url": dom,
                "ips": [],
                "cdns": [],
                "cdns_by_names": [],
                "not_cymru_cdn": False,
                # measurement results
                "cnames": [],
                "cnames_cdns": [],
                "headers": [],
                "headers_cdns": [],
                "cymru_whois": [],
                "cymru_whois_cdns": [],
                "all_cymru_data": [],
                # legacy keys
                "whois_data": [],
            }
            self.domains.append(dom_in)

class cdnCheck:
    """cdnCheck runs analysis and stores discovered data in Domain object."""

    def __init__(self):
        """Initialize the orchestrator of analysis."""
        self.running = False
    
    def ip_whois_bulk_lookup(self, pot: DomainPot, verbose: bool = False) -> int:
        """Get IP addresses for all domains and whois information, where available."""
        start_time_ip = time()
        # get all IPs
        lookupIPs = []
        for dom in pot.domains:
            if len(dom["cdns_by_names"])==0:
                self.ip(dom)
                for ip in dom["ips"]:
                    if ip not in pot.ips.keys():
                        pot.ips[ip] = []
                        lookupIPs.append(ip)
        end_time_ip = time()
        logger.debug(f"IP lookup time:{end_time_ip-start_time_ip}")

        # if there are no IPs, do not run
        if len(lookupIPs) == 0:
            logger.info("No IPs, skipping")
            return None
        
        # define a temp list to assign
        temp_cymru = []
        tc_response = ""
        
        # build the content
        tc_content = "begin\n"
        for ip in lookupIPs:
            tc_content += f'{ip}\n'
        tc_content += "255.255.255.255\nend"

        # run the whois lookup
        logger.info(f'Running team-cymru query for {len(lookupIPs)} IPs')
        
        # run the query
        tc_response = netcat("whois.cymru.com", 43, tc_content.encode())
        
        end_time_whois = time()
        logger.debug(f"Whois lookup time: {end_time_whois-end_time_ip}")
        # parse the results of the query, if they exist
        if tc_response:
            temp_cymru = parse_cymru_results(tc_response)
            
            for data in temp_cymru:
                if data[1] in pot.ips.keys():
                    # assign the data to the respective IP
                    pot.ips[data[1]] = data
            end_time_parse = time()
        logger.debug(f"Whois parse time: {end_time_parse-end_time_whois}")

        # re-assign the whois info to each domain
        for dom in pot.domains:
            if len(dom["cdns_by_names"]) == 0:
                for ip in dom["ips"]:
                    # get the whois info
                    whois = pot.ips[ip]
                    if len(whois)>2:
                        if whois[2] is not None and whois[2] not in dom["cymru_whois"]:
                            dom["cymru_whois"].append(whois[2])

                        # assign the full results to the domain
                        dom["all_cymru_data"].append(whois)
                # classify CDNs for that domain
                if len(dom["cymru_whois"]) > 0 and not None:
                    self.id_cdn(dom, "cymru_whois")
        end_time_reassign = time()

        logger.debug(f"Whois reassign time: {end_time_reassign-end_time_parse}")
        return 0
    
    def full_data_digest(self, pot: DomainPot, verbose: bool = False) -> int:
        """Digest all data collected and assign to CDN list."""
        return_code = 1
        for dom in pot.domains:
            # if there are no CDNs for this domain, digest data
            if len(dom["cdns_by_names"])==0:
                # cymru_whois_cdns, cnames_cdns, headers_cdns
                
                # only whois
                if len(dom["cymru_whois_cdns"])>0 and len(dom["cnames_cdns"])==0:
                    dom["cdns_by_names"] = dom["cymru_whois_cdns"]
                # only cname
                elif len(dom["cnames_cdns"])>0 and len(dom["cymru_whois_cdns"])==0:
                    dom["cdns_by_names"] = dom["cnames_cdns"]
                # if there are cname and whois, deal with clashes
                elif len(dom["cymru_whois_cdns"])>0 and len(dom["cnames_cdns"])>0:
                    whois_set = set(dom["cymru_whois_cdns"])
                    cname_set = set(dom["cnames_cdns"])
                    header_set = set(dom["headers_cdns"])

                    who_cna_int = whois_set.intersection(cname_set)
                    who_hea_int = whois_set.intersection(header_set)
                    cna_hea_int = cname_set.intersection(header_set)
                    
                    # cname and whois matches
                    if len(who_cna_int)>0:
                        dom["cdns_by_names"] = list(who_cna_int)
                    # whois and headers tiebreak
                    elif len(who_hea_int)>0:
                        dom["cdns_by_names"] = list(who_hea_int)
                    # cname and headers tiebreak
                    elif len(cna_hea_int)>0:
                        dom["cdns_by_names"] = list(cna_hea_int)
                    # finally, just use whois
                    else:
                        dom["cdns_by_names"] = dom["cymru_whois_cdns"]
            
            if len(dom["cdns_by_names"])>0:
                return_code = 0
        return return_code
    
    def cname_lookup(
        self,
        pot: DomainPot,
        timeout: int,
        agent: str,
        verbose: bool = False,
    ) -> int:
        """Runs CNAME lookups for all domains"""
        extra_count = 0
        total_cname_time = 0.0
        
        for dom in pot.domains:
            extra_count += 1
            start_cname = time()
            # if the CNAME lookup hasn't been successful
            if len(dom["cnames"]) == 0:
                self.cname(dom, timeout)
            
            # classify CDNs for that domain
            if len(dom["cnames"]) > 0 and not None:
                self.id_cdn(dom, "cnames")
            
            finish_cname = time()
            total_cname_time += finish_cname-start_cname
        
        logger.debug(f"Total CNAME Time: {total_cname_time}")
        logger.info(f"Extra checks done: {extra_count}")
        # Return to calling function
        return 0
    
    def tiebreak_check(
        self,
        pot: DomainPot,
        timeout: int,
        agent: str,
        verbose: bool = False,
    ) -> int:
        """Checks whether domains are tied on WHOIS and CNAME CDNs and, if so, performs a headers tiebreak"""
        tiebreak_count = 0
        start_tiebreak = time()

        for dom in pot.domains:

            cymru_set = set(dom["cymru_whois_cdns"])
            cname_set = set(dom["cnames_cdns"])

            # there are results for WHOIS and CNAME
            if (len(cymru_set)>0 and len(cname_set)>0 and len(cymru_set.intersection(cname_set))==0):
                # if the headers lookup hasn't been done
                if len(dom["headers"]) == 0:
                    tiebreak_count += 1
                    self.https_lookup(dom, timeout, agent, verbose)
                
                # classify CDNs for that domain
                if len(dom["headers"]) > 0 and not None:
                    self.id_cdn(dom, "headers")
        
        finish_tiebreak = time()
        logger.debug(f"Total tiebreak time: {finish_tiebreak-start_tiebreak}")
        logger.info(f"Tiebreaks done: {tiebreak_count}")
        # Return to calling function
        return 0
    
    def ip(self, dom: dict) -> List[int]:
        """Determine IP addresses the domain resolves to."""
        dom_list: List[str] = [dom["url"], "www." + dom["url"]]
        return_codes = []
        ip_list = []
        for domain in dom_list:
            try:
                # Seutp resolver and timeouts
                resolver = Resolver()
                resolver.nameservers = ['8.8.8.8','1.1.1.1']
                resolver.lifetime = LIFETIME
                # query the domain
                response = resolver.resolve(domain)
                # Assign any found IP addresses to the object
                for ip in response:
                    if str(ip.address) not in ip_list and str(ip.address) not in dom["ips"]:
                        ip_list.append(str(ip.address))
            except NoAnswer:
                return_codes.append(1)
            except NoNameservers:
                return_codes.append(2)
            except NXDOMAIN:
                return_codes.append(3)
            except Timeout:
                return_codes.append(4)

        # Append all addresses into IP_list
        for addr in ip_list:
            dom["ips"].append(addr)
        # Return listing of error codes
        return return_codes

    def cname(self, dom: dict, timeout: int) -> List[int]:
        """Collect CNAME records on domain."""
        # List of domains to check
        dom_list = [dom["url"], "www." + dom["url"]]
        # Our codes to return
        return_code = []
        # Seutp resolver and timeouts
        resolver = Resolver()
        resolver.timeout = timeout
        resolver.lifetime = LIFETIME
        resolver.nameservers = ['8.8.8.8','1.1.1.1']
        cname_query = resolver.resolve
        # Iterate through all domains in list
        for domain in dom_list:
            try:
                response = cname_query(domain, "cname")
                dom["cnames"] = [record.to_text() for record in response]
            except NoAnswer:
                return_code.append(1)
            except NoNameservers:
                return_code.append(2)
            except NXDOMAIN:
                return_code.append(3)
            except Timeout:
                return_code.append(4)
        return return_code

    def https_lookup(
        self, dom: dict, timeout: int, agent: str, verbose: bool
    ) -> int:
        """Read 'server' and 'via' header for CDN hints."""
        try:
            session = Session()
            retry = Retry(connect=3, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            response = session.get(f'https://{dom["url"]}', headers={"User-Agent": agent}, timeout=timeout)

            # Define headers to check for the response
            # to grab strings for later parsing.
            for value in ["server", "via"]:
                if (
                    value in response.headers.keys() 
                    and response.headers[value] is not None
                    and response.headers[value] not in dom["headers"]
                ):
                    dom["headers"].append(response.headers[value])
        except Exception as e:
            logger.warning(f'[{dom["url"]}]: {e}')
        return 0

    def id_cdn(self, dom: dict, list_type: str):
        """
        Identify any CDN name in list received.

        All of these will be doing some sort of substring analysis
        on each string from any list passed to it. This will help
        us identify the CDN which could be used.
        """
        # ensure the list is in the domain
        if list_type not in dom.keys():
            logger.warning(f"Error: {list_type} not in domain dict")
        # ensure the list_cdns is in the domain
        if list_type+"_cdns" not in dom.keys():
            logger.warning(f"Error: {list_type}_cdns not in domain dict")
        for data in dom[list_type]:
            # Make sure we do not try to analyze None type data
            if data is None:
                continue
            # Check the CDNs standard list keys and values
            for url, name in CDNs.items():
                if (
                    (url.lower().replace(" ", "") in data.lower().replace(" ", "")
                    or name.lower().replace(" ", "") in data.lower().replace(" ", ""))
                    and name not in dom[list_type+"_cdns"]
                ):
                    dom[list_type+"_cdns"].append(name)

def netcat(hostname: str, port: int, content: bytes) -> str | None:
    '''
    Creates a netcat-style socket to the hostname and port, sends content and returns string representation of the received data, or None if nothing received
    '''
    
    # create the socket
    s = socket(AF_INET, SOCK_STREAM)

    # set the socket timeout
    s.settimeout(120)
    
    # connect and send data
    s.connect((hostname, port))
    s.sendall(content)
    
    # receive data
    rstr = ""
    while "255.255.255.255" not in rstr:
        data = s.recv(1024)
        rstr += data.decode()
    
    # close the connection
    s.shutdown(SHUT_WR)
    s.close()
    
    # check that data was returned
    if len(rstr) == 0:
        return None

    # return the data
    return repr(rstr)

def parse_cymru_results(response: str) -> List[List[str]]:
    '''
    Parses the results of the Team-Cymru Whois Lookup. Returns a list of lists. FindCDN uses only the AS Name. Each sub-list contains data in the order:
    AS | IP | AS Name
    '''

    # get lines list
    response_lines = response.split("\\n")
    
    lines_lists: List[List[str]] = []

    # convert lines into lists
    for line in response_lines:
        # skip lines without relevant IP info
        if "|" not in line or "255.255.255.255" in line:
            continue
        # remove backslashes if present
        if "\\" in line:
            line = line.replace("\\","")
        # split on separator and strip
        line_list = [x.strip() for x in line.split("|")]
        lines_lists.append(line_list)

    return lines_lists