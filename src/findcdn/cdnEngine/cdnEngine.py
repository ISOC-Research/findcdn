"""
Summary: cdnEngine orchestrates CDN detection of domains.

Description: cdnEngine is a simple solution for detection
if a given domain or set of domains use a CDN.
"""

# Standard Python Libraries
import concurrent.futures
import math
import os
from typing import List, Tuple, Dict
import logging

# Third-Party Libraries
from tqdm import tqdm

# Internal Libraries
from . import detectCDN

# start logging
logger = logging.getLogger(__name__)

def split_list(lst, size):
    """Returns split of input list into lists of given size"""
    split_lists = []
    for i in range(0, len(lst), size):
        split_lists.append(lst[i:i + size])
    return split_lists

class Chef:
    """Chef will run analysis on the domains in the DomainPot."""

    def __init__(
        self,
        domains: list[str],
        dom_count: int,
        threads: int,
        timeout: int,
        user_agent: str,
        verbose: bool = False,
    ):
        """Give the chef the pot to use."""
        self.domain_count = dom_count
        self.verbose: bool = verbose
        self.timeout: int = timeout
        self.agent = user_agent

        # Determine thread count
        if not (threads and threads != 0):
            # No user defined threads, get it from os.cpu_count()
            cpu_count = os.cpu_count()
            if cpu_count is None:
                cpu_count = 1
            threads = cpu_count

        # calculate domains per thread using a reverse floor function
        dpt = -(len(domains) // -threads)

        # split the domains into multiple smaller lists corresponding to the thread count
        domain_lists = split_list(domains, dpt)
        
        # for the domains of each list, create a new pot
        new_pots = []
        for dom_list in domain_lists:
            new_pots.append(detectCDN.DomainPot(dom_list))
        pots = new_pots

        self.pots = pots
        self.threads = threads

    def analyze_domains(self):
        """Run analysis on the internal domain pool using detectCDN library."""
        # Use Concurrent futures to multithread with pools
        job_count = 0

        if self.verbose:
            # Give user information about the run:
            print(f"Using {self.threads} threads with a {self.timeout} second timeout to get IPs")
        logger.info(f"Using {self.threads} threads with a {self.timeout} second timeout to get IPs")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            job_count = self.domain_count

            # Assign workers and assign to results list
            results = {
                executor.submit(
                    chef_executor,
                    self,
                    pot,
                    self.timeout,
                    self.agent,
                    self.verbose,
                )
                for pot in self.pots
            }

            # Comb future objects for completed task pool.
            for future in concurrent.futures.as_completed(results):
                try:
                    # Try and grab feature result to dequeue job
                    future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError as e:
                    # Tell us we dropped it. Should log this instead.
                    if self.verbose:
                        print(f"Dropped due to: {e}")
                    logger.info(f"Dropped due to: {e}")

        # Return the amount of jobs done and error code
        return job_count

def chef_executor(
    self: Chef,
    pot: detectCDN.DomainPot,
    timeout: int,
    user_agent: str,
    verbosity: bool,
):
    """Attempt to make the method "threadsafe" by giving each worker its own detector."""
    # Define detector
    detective = detectCDN.cdnCheck()

    # Run checks
    try:
        # get IPs and Whois info
        detective.ip_whois_bulk_lookup(pot, verbosity)

        # run cname checks on domains without CDNs
        detective.cname_lookup(pot, timeout, user_agent, verbosity)

        # tiebreak check
        detective.tiebreak_check(pot, timeout, user_agent, verbosity)

        # digest remaining data
        detective.full_data_digest(pot, verbosity)

    except Exception as e:
        # Incase some uncaught error somewhere
        if verbosity:
            print(f"Exception: {e}")
        logger.error(f"Exception: {e}")
        return 1

    # Return 0 for success
    return 0


def run_checks(
    domains: List[str],
    threads: int,
    timeout: int,
    user_agent: str,
    verbose: bool = False,
    double: bool = False,
) -> Tuple[List[dict], int]:
    """Orchestrate the use of DomainPot and Chef."""

    # # Determine thread count
    # if not (threads and threads != 0):
    #     # No user defined threads, get it from os.cpu_count()
    #     cpu_count = os.cpu_count()
    #     if cpu_count is None:
    #         cpu_count = 1
    #     threads = cpu_count

    # # calculate domains per thread using a reverse floor function
    # dpt = -(len(domains) // -threads)

    # # split the domains into multiple smaller lists corresponding to the thread count
    # domain_lists = split_list(domains, dpt)
    
    # # for the domains of each list, create a new pot
    # new_pots = []
    # for dom_list in domain_lists:
    #     new_pots.append(detectCDN.DomainPot(dom_list))
    # pots = new_pots

    # Our chef to manage pot
    chef = Chef(domains, len(domains), threads, timeout, user_agent, verbose)

    # Run analysis for all domains
    cnt = chef.analyze_domains()

    # if double, run analysis again
    if double:
        cnt += chef.analyze_domains()

    # convert the separate domain pots into one list for output
    domains_results = [domain for pot in chef.pots for domain in pot.domains]

    # Return all domains in form domain_pool, job count
    return (domains_results, cnt)
