"""
Summary: This is the main runner for detectCDn.

Description: The detectCDN library is meant to show what CDNs a domain may be using
"""

# Standard Python Libraries
from http.client import RemoteDisconnected
from ssl import CertificateError, SSLError
from typing import List
from urllib import request as request
from urllib.error import URLError
from socket import socket, AF_INET, SOCK_STREAM, SHUT_WR
from typing import Dict
from time import time
from struct import unpack
from requests import get

# Third-Party Libraries
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Resolver, Timeout, query
from ipwhois import HTTPLookupError, IPDefinedError, IPWhois
from ipwhois.exceptions import ASNRegistryError
from bs4 import BeautifulSoup

# Internal Libraries
from .cdn_config import COMMON, CDNs, CDNs_rev
from .cdn_err import NoIPaddress

# Global variables
LIFETIME = 10

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
                "cdns_by_name": [],
                "not_cymru_cdn": False,
                "cdn_present": False,
                # measurement results
                "cnames": [],
                "cnames_cdns": [],
                "headers": [],
                "headers_cdns": [],
                "page_links": [],
                "page_links_relevant": [],
                "page_links_cdns": [],
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
    
    def get_ips_whois(self, pot: DomainPot, verbose: bool = False) -> int:
        """Get IP addresses for all domains and whois information, where available."""
        start_time_ip = time()
        # get all IPs
        lookupIPs = []
        for dom in pot.domains:
            if not dom["cdn_present"]:
                self.ip(dom)
                for ip in dom["ips"]:
                    if ip not in pot.ips.keys():
                        pot.ips[ip] = []
                        lookupIPs.append(ip)
        end_time_ip = time()
        print("IP lookup time:",end_time_ip-start_time_ip)

        # if there are no IPs, do not run
        if len(lookupIPs) == 0:
            print("No IPs, skipping")
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
        print(f'Running team-cymru query for {len(lookupIPs)} IPs')
        
        # run the query
        tc_response = netcat("whois.cymru.com", 43, tc_content.encode())
        # print(tc_response)
        end_time_whois = time()
        print("Whois lookup time:",end_time_whois-end_time_ip)
        # parse the results of the query, if they exist
        if tc_response:
            temp_cymru = parse_cymru_results(tc_response)
            
            for data in temp_cymru:
                if data[1] in pot.ips.keys():
                    # assign the data to the respective IP
                    pot.ips[data[1]] = data
            end_time_parse = time()
        print("Whois parse time:",end_time_parse-end_time_whois)

        # re-assign the whois info to each domain
        for dom in pot.domains:
            if not dom["cdn_present"]:
                for ip in dom["ips"]:
                    # get the whois info
                    whois = pot.ips[ip]
                    # print(whois)
                    if len(whois)>2:
                        if whois[2] is not None and whois[2] not in dom["cymru_whois"]:
                            dom["cymru_whois"].append(whois[2])

                        # assign the full results to the domain
                        dom["all_cymru_data"].append(whois)
                # classify CDNs for that domain
                if len(dom["cymru_whois"]) > 0 and not None:
                    self.id_cdn(dom, "cymru_whois")
        end_time_reassign = time()

        print("Whois reassign time:",end_time_reassign-end_time_parse)
        return 0
    
    def full_data_digest(self, pot: DomainPot, verbose: bool = False) -> int:
        """Digest all data collected and assign to CDN list."""
        return_code = 1
        for dom in pot.domains:
            # if there are no CDNs, digest data
            if not dom["cdn_present"]:
                # Iterate through all attributes for substrings
                if len(dom["cymru_whois"]) > 0 and not None:
                    self.id_cdn(dom, "cymru_whois")
                    return_code = 0
                if len(dom["cnames"]) > 0 and not None:
                    self.id_cdn(dom, "cnames")
                    return_code = 0
                if len(dom["headers"]) > 0 and not None:
                    self.id_cdn(dom, "headers")
                    return_code = 0
                if len(dom["page_links"]) > 0 and not None:
                    self.id_cdn(dom, "page_links")
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
        
        print("total cname:",total_cname_time)
        print("extra checks done:",extra_count)
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

            if len(cymru_set)>0 and len(cname_set)>0 and len(cymru_set.intersection(cname_set))==0:
                # if the headers lookup hasn't been done
                if len(dom["headers"]) == 0:
                    tiebreak_count += 1
                    self.headers_lookup(dom, timeout, agent, False, verbose)
                
                # classify CDNs for that domain
                if len(dom["headers"]) > 0 and not None:
                    self.id_cdn(dom, "headers")
                if len(dom["page_links"]) > 0 and not None:
                    self.id_cdn(dom, "page_links")
        
        finish_tiebreak = time()
        print("total tiebreak time:", finish_tiebreak-start_tiebreak)
        print("tiebreaks done:", tiebreak_count)
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

    def headers_lookup(
        self, dom: dict, timeout: int, agent: str, interactive: bool, verbose: bool
    ) -> int:
        """Read 'server' and 'via' header for CDN hints."""
        try:
            # get the domain
            response = get(f'https://{dom["url"]}', headers={"User-Agent": agent}, timeout=timeout)

            # Define headers to check for the response
            # to grab strings for later parsing.
            for value in ["server", "via"]:
                if (
                    value in response.headers.keys() 
                    and response.headers[value] is not None
                    and response.headers[value] not in dom["headers"]
                ):
                    dom["headers"].append(response.headers[value])
            
            # parse the response HTML
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find all elements with the tag <a>
            links = soup.find_all("a")

            # add all external links to the array
            for link in links:
                href = link.get("href")
                if href is not None and href.startswith("http"):
                    dom["page_links"].append(href)
        except Exception as e:
            # if interactive or verbose:
            print(f'[{dom["url"]}]: {e}')
        return 0
    
    def cymru_lookup(self, dom: dict, interactive: bool, verbose: bool) -> int | None:
        if interactive or verbose:
            print(f'Running team-cymru query for {dom["url"]}, {len(dom["ips"])} IPs')

        # if there are no IPs, do not run
        if len(dom["ips"]) == 0:
            print("No IPs, skipping")
            return None
        
        # define a temp list to assign
        temp_cymru = []
        tc_response = ""
        
        # build the content
        tc_content = "begin\n"
        for ip in dom["ips"]:
            tc_content += f'{ip}\n'
        tc_content += "255.255.255.255\nend"

        # run the query
        tc_response = netcat("whois.cymru.com", 43, tc_content.encode())

        # parse the results of the query, if they exist
        if tc_response:
            temp_cymru = parse_cymru_results(tc_response)

            # reduce the cymru results into whois-style responses for FindCDN
            for res in temp_cymru:
                if res[2] is not None and res[2] not in dom["cymru_whois"]:
                    dom["cymru_whois"].append(res[2])
            
            # assign the full results to the domain
            dom["all_cymru_data"] = temp_cymru

        return 0
    
    def whois(self, dom: dict, interactive: bool, verbose: bool) -> int:
        """Scrape WHOIS data for the org or asn_description."""
        # Make sure we have Ip addresses to check
        try:
            if len(dom["ips"]) <= 0:
                raise NoIPaddress
        except NoIPaddress:
            return 1
        # Define temp list to assign
        whois_data = []
        # Iterate through all the IP addresses in object
        for ip in dom["ips"]:
            try:
                response = IPWhois(ip)
                # These two should be where we can find substrings hinting to CDN
                try:
                    org = response.lookup_whois()["asn_description"]
                    if org != "BAREFRUIT-ERRORHANDLING":
                        whois_data.append(org)
                except AttributeError:
                    pass
                try:
                    org = response.lookup_rdap()["network"]["name"]
                    if org != "BAREFRUIT-ERRORHANDLING":
                        whois_data.append(org)
                except AttributeError:
                    pass
            except HTTPLookupError:
                pass
            except IPDefinedError:
                pass
            except ASNRegistryError:
                pass
            except Exception as e:
                if interactive or verbose:
                    print(f'[{dom["url"]} for {ip}]: {e}')
        for data in whois_data:
            if data not in dom["whois_data"]:
                dom["whois_data"].append(data)
        # Everything was successful
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
            print("Error:", list_type,"not in domain dict")
        # ensure the list_cdns is in the domain
        if list_type+"_cdns" not in dom.keys():
            print("Error:", list_type+"_cdns not in domain dict")
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

                    # add relevant page links if a CDN has been identified from them
                    if list_type == "page_links":
                        dom["page_links_relevant"].append(data)

    def data_digest(self, dom: dict) -> int:
        """Digest all data collected and assign to CDN list."""
        return_code = 1
        # Iterate through all attributes for substrings
        if len(dom["cnames"]) > 0 and not None:
            self.id_cdn(dom, dom["cnames"], "cnames")
            return_code = 0
        if len(dom["headers"]) > 0 and not None:
            self.id_cdn(dom, dom["headers"], "headers")
            return_code = 0
        if len(dom["whois_data"]) > 0 and not None:
            self.id_cdn(dom, dom["whois_data"], "whois_data")
            return_code = 0
        if len(dom["cymru_whois"]) > 0 and not None:
            self.id_cdn(dom, dom["cymru_whois"], "cymru_whois")
            return_code = 0
        return return_code

    def all_checks(
        self,
        dom: dict,
        timeout: int,
        agent: str,
        verbose: bool = False,
        interactive: bool = False,
    ) -> int:
        """Option to run everything in this library then digest."""
        # Obtain each attributes data
        # self.ip(dom)
        # self.cname(dom, timeout)
        # self.https_lookup(dom, timeout, agent, interactive, verbose)
        # self.cymru_lookup(dom, interactive, verbose)
        # self.whois(dom, interactive, verbose)

        # Digest the data
        return_code = self.data_digest(dom)

        # Extra case if we want verbosity for each domain check
        if verbose:
            if len(dom["cdns"]) > 0:
                print(f'{dom["url"]} has the following CDNs:\n{dom["cdns"]}')
            else:
                print(f'{dom["url"]} does not use a CDN')

        # Return to calling function
        return return_code

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

    # # remove byte characters from string
    # if "'b'" in rstr:
    #     rstr = rstr.replace("'b'","")
    
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