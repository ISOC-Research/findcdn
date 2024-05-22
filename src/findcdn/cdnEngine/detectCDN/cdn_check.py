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

# Third-Party Libraries
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, Resolver, Timeout, query
from ipwhois import HTTPLookupError, IPDefinedError, IPWhois
from ipwhois.exceptions import ASNRegistryError

# Internal Libraries
from .cdn_config import COMMON, CDNs, CDNs_rev
from .cdn_err import NoIPaddress

# Global variables
LIFETIME = 10

class Domain:
    """Domain class allows for storage of metadata on domain."""

    def __init__(
        self,
        url: str,
        ip: List[str] = [],
        cnames: List[str] = [],
        cdns: List[str] = [],
        cdns_by_name: List[str] = [],
        namsrvs: List[str] = [],
        headers: List[str] = [],
        whois_data: List[str] = [],
        cymru_whois_data: List[str] = [],
        cymru_data: List[List[str]] = [],
    ):
        """Initialize object to store metadata on domain in url."""
        self.url = url
        self.ip = ip
        self.cnames = cnames
        self.cdns = cdns
        self.cdns_by_name = cdns_by_name
        self.namesrvs = namsrvs
        self.headers = headers
        self.whois_data = whois_data
        self.cymru_whois_data = cymru_whois_data
        self.cymru_data = cymru_data
        self.not_cymru_cdn = False
        self.cdn_present = False

class DomainPot:
    """DomainPot defines the "pot" which Domain objects are stored."""

    def __init__(self, domains: List[str]):
        """Define the pot for the Chef to use."""
        self.domains: List[Domain] = []
        self.ips: Dict[str,List[str]] = {}

        # Convert to list of type domain
        for dom in domains:
            dom_in = Domain(
                dom, list(), list(), list(), list(), list(), list(), list(), list(), list()
            )
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
        for dom in pot.domains:
            self.ip(dom)
            for ip in dom.ip:
                pot.ips[ip] = []
        end_time_ip = time()

        # if there are no IPs, do not run
        if len(pot.ips) == 0:
            print("No IPs, skipping")
            return None
        
        # define a temp list to assign
        temp_cymru = []
        tc_response = ""
        
        # build the content
        tc_content = "begin\nverbose\n"
        for ip in pot.ips:
            tc_content += f"{ip}\n"
        tc_content += "end"

        # run the whois lookup
        if verbose:
            print(f"Running team-cymru query for {len(pot.ips)} IPs")
        
        # run the query
        tc_response = netcat("whois.cymru.com", 43, tc_content.encode())
        print(tc_response)
        end_time_whois = time()
        # parse the results of the query, if they exist
        if tc_response:
            temp_cymru = parse_cymru_results(tc_response)
            
            for data in temp_cymru:
                # assign the data to the respective IP
                pot.ips[data[1]] = data
            end_time_parse = time()

        # re-assign the whois info to each domain
        for dom in pot.domains:
            for ip in dom.ip:
                # get the whois info
                whois = pot.ips[ip]
                # print(whois)
                if len(whois)>6:
                    if whois[6] is not None and whois[6] not in dom.cymru_whois_data:
                        dom.cymru_whois_data.append(whois[6])

                    # assign the full results to the domain
                    dom.cymru_data.append(whois)
        end_time_reassign = time()

        print("IP lookup time:",end_time_ip-start_time_ip)
        print("Whois lookup time:",end_time_whois-end_time_ip)
        print("Whois parse time:",end_time_parse-end_time_whois)
        print("Whois reassign time:",end_time_reassign-end_time_parse)
        
        return 0

    def ip(self, dom: Domain) -> List[int]:
        """Determine IP addresses the domain resolves to."""
        dom_list: List[str] = [dom.url, "www." + dom.url]
        return_codes = []
        ip_list = []
        for domain in dom_list:
            try:
                # Query the domain
                response = query(domain)
                # Assign any found IP addresses to the object
                for ip in response:
                    if str(ip.address) not in ip_list and str(ip.address) not in dom.ip:
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
            dom.ip.append(addr)
        # Return listing of error codes
        return return_codes

    def cname(self, dom: Domain, timeout: int) -> List[int]:
        """Collect CNAME records on domain."""
        # List of domains to check
        dom_list = [dom.url, "www." + dom.url]
        # Our codes to return
        return_code = []
        # Seutp resolver and timeouts
        resolver = Resolver()
        resolver.timeout = timeout
        resolver.lifetime = LIFETIME
        cname_query = resolver.query
        # Iterate through all domains in list
        for domain in dom_list:
            try:
                response = cname_query(domain, "cname")
                dom.cnames = [record.to_text() for record in response]
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
        self, dom: Domain, timeout: int, agent: str, interactive: bool, verbose: bool
    ) -> int:
        """Read 'server' header for CDN hints."""
        # List of domains with different protocols to check.
        PROTOCOLS = ["https://", "https://www."]
        # Iterate through all protocols
        for PROTOCOL in PROTOCOLS:
            try:
                # Some domains only respond when we have a User-Agent defined.
                req = request.Request(
                    PROTOCOL + dom.url,
                    data=None,
                    headers={"User-Agent": agent},
                )
                # Making the timeout 50 as to not hang thread.
                response = request.urlopen(req, timeout=timeout)  # nosec
            except URLError:
                continue
            except RemoteDisconnected:
                continue
            except CertificateError:
                continue
            except ConnectionResetError:
                continue
            except SSLError:
                continue
            except Exception as e:
                # Define an exception just in case we missed one.
                if interactive or verbose:
                    print(f"[{e}]: https://{dom.url}")
                continue
            # Define headers to check for the response
            # to grab strings for later parsing.
            HEADERS = ["server", "via"]
            for value in HEADERS:
                if (
                    response.headers[value] is not None
                    and response.headers[value] not in dom.headers
                ):
                    dom.headers.append(response.headers[value])
        return 0
    
    def cymru_lookup(self, dom: Domain, interactive: bool, verbose: bool) -> int | None:
        if interactive or verbose:
            print(f"Running team-cymru query for {dom.url}, {len(dom.ip)} IPs")

        # if there are no IPs, do not run
        if len(dom.ip) == 0:
            print("No IPs, skipping")
            return None
        
        # define a temp list to assign
        temp_cymru = []
        tc_response = ""
        
        # build the content
        tc_content = "begin\nverbose\n"
        for ip in dom.ip:
            tc_content += f"{ip}\n"
        tc_content += "end"

        # run the query
        tc_response = netcat("whois.cymru.com", 43, tc_content.encode())

        # parse the results of the query, if they exist
        if tc_response:
            temp_cymru = parse_cymru_results(tc_response)

            # reduce the cymru results into whois-style responses for FindCDN
            for res in temp_cymru:
                if res[6] is not None and res[6] not in dom.cymru_whois_data:
                    dom.cymru_whois_data.append(res[6])
            
            # assign the full results to the domain
            dom.cymru_data = temp_cymru

        return 0
    
    def whois(self, dom: Domain, interactive: bool, verbose: bool) -> int:
        """Scrape WHOIS data for the org or asn_description."""
        # Make sure we have Ip addresses to check
        try:
            if len(dom.ip) <= 0:
                raise NoIPaddress
        except NoIPaddress:
            return 1
        # Define temp list to assign
        whois_data = []
        # Iterate through all the IP addresses in object
        for ip in dom.ip:
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
                    print(f"[{e}]: {dom.url} for {ip}")
        for data in whois_data:
            if data not in dom.whois_data:
                dom.whois_data.append(data)
        # Everything was successful
        return 0

    def CDNid(self, dom: Domain, data_blob: List, list_type: str):
        """
        Identify any CDN name in list received.

        All of these will be doing some sort of substring analysis
        on each string from any list passed to it. This will help
        us identify the CDN which could be used.
        """
        for data in data_blob:
            # Make sure we do not try to analyze None type data
            if data is None:
                continue
            # Check the CDNs standard list
            for url in CDNs:
                if (
                    url.lower().replace(" ", "") in data.lower().replace(" ", "")
                    and url not in dom.cdns
                ):
                    dom.cdns.append(url)
                    dom.cdns_by_name.append(CDNs[url])
                    if list_type != "cymru_whois_data":
                        dom.not_cymru_cdn = True

            # Check the CDNs reverse list
            for name in CDNs_rev:
                if name.lower() in data.lower() and CDNs_rev[name] not in dom.cdns:
                    dom.cdns.append(CDNs_rev[name])
                    dom.cdns_by_name.append(name)
                    if list_type != "cymru_whois_data":
                        dom.not_cymru_cdn = True

            # Check the CDNs Common list:
            for name in COMMON.keys():
                if (
                    name.lower().replace(" ", "") in data.lower().replace(" ", "")
                    and CDNs_rev[name] not in dom.cdns
                ):
                    dom.cdns.append(CDNs_rev[name])
                    dom.cdns_by_name.append(name)
                    if list_type != "cymru_whois_data":
                        dom.not_cymru_cdn = True

    def data_digest(self, dom: Domain) -> int:
        """Digest all data collected and assign to CDN list."""
        return_code = 1
        # Iterate through all attributes for substrings
        if len(dom.cnames) > 0 and not None:
            self.CDNid(dom, dom.cnames, "cnames")
            return_code = 0
        if len(dom.headers) > 0 and not None:
            self.CDNid(dom, dom.headers, "headers")
            return_code = 0
        if len(dom.namesrvs) > 0 and not None:
            self.CDNid(dom, dom.namesrvs, "namesrvs")
            return_code = 0
        if len(dom.whois_data) > 0 and not None:
            self.CDNid(dom, dom.whois_data, "whois_data")
            return_code = 0
        if len(dom.cymru_whois_data) > 0 and not None:
            self.CDNid(dom, dom.cymru_whois_data, "cymru_whois_data")
            return_code = 0
        return return_code

    def all_checks(
        self,
        dom: Domain,
        timeout: int,
        agent: str,
        verbose: bool = False,
        interactive: bool = False,
    ) -> int:
        """Option to run everything in this library then digest."""
        # Obtain each attributes data
        # self.ip(dom)
        self.cname(dom, timeout)
        self.https_lookup(dom, timeout, agent, interactive, verbose)
        # self.cymru_lookup(dom, interactive, verbose)
        # self.whois(dom, interactive, verbose)

        # Digest the data
        return_code = self.data_digest(dom)

        # Extra case if we want verbosity for each domain check
        if verbose:
            if len(dom.cdns) > 0:
                print(f"{dom.url} has the following CDNs:\n{dom.cdns}")
            else:
                print(f"{dom.url} does not use a CDN")

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
    data = s.recv(4096)
    
    # close the connection
    s.shutdown(SHUT_WR)
    s.close()
    
    # check that data was returned
    if len(data) == 0:
        return None

    # return the data
    return repr(data)

def parse_cymru_results(response: str) -> List[List[str]]:
    '''
    Parses the results of the Team-Cymru Whois Lookup. Returns a list of lists. FindCDN uses only the AS Name. Each sub-list contains data in the order:
    AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    '''

    # get lines list
    response_lines = response.split("\\n")

    # remove first line if it is info
    if "Bulk mode" in response_lines[0]:
        response_lines.pop(0)
    
    # remove last line if info
    if response_lines[-1] == "'":
        response_lines.pop(-1)
    
    lines_lists: List[List[str]] = []

    # convert lines into lists
    for line in response_lines:
        # split on separator and strip
        line_list = [x.strip() for x in line.split("|")]
        lines_lists.append(line_list)

    return lines_lists