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

# Third-Party Libraries
from tqdm import tqdm

# Internal Libraries
from . import detectCDN

class Chef:
    """Chef will run analysis on the domains in the DomainPot."""

    def __init__(
        self,
        pot: detectCDN.DomainPot,
        threads: int,
        timeout: int,
        user_agent: str,
        interactive: bool = False,
        verbose: bool = False,
    ):
        """Give the chef the pot to use."""
        self.pot: detectCDN.DomainPot = pot
        self.pbar: tqdm = interactive
        self.verbose: bool = verbose
        self.timeout: int = timeout
        self.agent = user_agent
        self.interactive = interactive

        # Determine thread count
        if threads and threads != 0:
            # Threads defined by user assign
            self.threads = threads
        else:
            # No user defined threads, get it from os.cpu_count()
            cpu_count = os.cpu_count()
            if cpu_count is None:
                cpu_count = 1
            self.threads = cpu_count  # type: ignore

    def grab_cdn(self, second_run: bool = False):  # type: ignore
        """Check for CDNs used be domain list."""
        # Use Concurrent futures to multithread with pools
        job_count = 0

        if self.verbose and not second_run:
            # Give user information about the run:
            print(f"Using {self.threads} threads with a {self.timeout} second timeout")
            print(f"User Agent: {self.agent}\n")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            job_count = len(self.pot.domains)
            # Setup pbar with correct amount size
            if self.pbar:
                pbar = tqdm(total=job_count)

            # Assign workers and assign to results list
            results = {
                executor.submit(
                    chef_executor,
                    domain,
                    self.timeout,
                    self.agent,
                    self.verbose,
                    self.interactive,
                )
                for domain in self.pot.domains
            }

            # Comb future objects for completed task pool.
            for future in concurrent.futures.as_completed(results):
                try:
                    # Try and grab feature result to dequeue job
                    future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError as e:
                    # Tell us we dropped it. Should log this instead.
                    if self.interactive or self.verbose:
                        print(f"Dropped due to: {e}")

                # Update status bar if allowed
                if self.pbar:
                    # We type ignore these as its "illegal" to access private attributes of an object
                    pending = f"Pending: {executor._work_queue.qsize()} jobs"  # type: ignore
                    threads = f"Threads: {len(executor._threads)}"  # type: ignore
                    pbar.set_description(f"[{pending}]==[{threads}]")
                    if self.pbar is not None:
                        pbar.update(1)
                    else:
                        pass

        # Return the amount of jobs done and error code
        return job_count
    
    def grab_ips(self):  # type: ignore
        """Get IPs for all domains."""
        # Use Concurrent futures to multithread with pools
        job_count = 0

        if self.verbose:
            # Give user information about the run:
            print(f"Using {self.threads} threads with a {self.timeout} second timeout to get IPs")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            job_count = len(self.pot.domains)
            # Setup pbar with correct amount size
            if self.pbar:
                pbar = tqdm(total=job_count)

            # Assign workers and assign to results list
            results = {
                executor.submit(
                    chef_ip_executor,
                    self,
                    self.pot,
                    self.timeout,
                    self.agent,
                    self.verbose,
                    self.interactive,
                )
            }

            # Comb future objects for completed task pool.
            for future in concurrent.futures.as_completed(results):
                try:
                    # Try and grab feature result to dequeue job
                    future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError as e:
                    # Tell us we dropped it. Should log this instead.
                    if self.interactive or self.verbose:
                        print(f"Dropped due to: {e}")

        # Return the amount of jobs done and error code
        return job_count

    def has_cdn(self):
        """For each domain, check if domain contains CDNS. If so, tick cdn_present to true."""
        cdn_count = 0
        for domain in self.pot.domains:
            if len(domain.cdns) > 0:
                domain.cdn_present = True
                cdn_count += 1
        print(len(self.pot.domains), ", cdn count:", cdn_count)

    def run_checks(self, double: bool = False) -> int:
        """Run analysis on the internal domain pool using detectCDN library."""
        cnt = self.grab_ips()

        if double:
            cnt += self.grab_ips()
        
        # cnt = self.grab_cdn(second_run=False)
        # self.has_cdn()

        # if double:
        #     cnt += self.grab_cdn(second_run=True)
        #     self.has_cdn()
        
        return cnt

def chef_executor(
    domain: detectCDN.Domain,
    timeout: int,
    user_agent: str,
    verbosity: bool,
    interactive: bool,
):
    """Attempt to make the method "threadsafe" by giving each worker its own detector."""
    # Define detector
    detective = detectCDN.cdnCheck()

    # Run checks
    try:
        if not domain.cdn_present:
            detective.all_checks(
                # Timeout is split by .4 so that each chunk can only take less than half.
                domain,
                verbose=verbosity,
                timeout=math.ceil(timeout * 0.4),
                agent=user_agent,
                interactive=interactive,
            )
    except Exception as e:
        # Incase some uncaught error somewhere
        if interactive or verbosity:
            print(f"An unusual exception has occurred:\n{e}")
        return 1

    # Return 0 for success
    return 0

def chef_ip_executor(
    self: Chef,
    pot: detectCDN.DomainPot,
    timeout: int,
    user_agent: str,
    verbosity: bool,
    interactive: bool,
):
    """Attempt to make the method "threadsafe" by giving each worker its own detector."""
    # Define detector
    detective = detectCDN.cdnCheck()

    # Run checks
    try:
        # get IPs and Whois info
        detective.get_ips_whois(pot, verbosity)

        # print("full data digest now")
        
        # # digest current data
        # detective.full_data_digest(pot, verbosity)

        # self.has_cdn()

        print("extra checks now")

        # run cname/header checks on domains without CDNs
        detective.extra_checks(pot, timeout, user_agent, verbosity)

        print("full data digest again")

        # digest remaining data
        detective.full_data_digest(pot, verbosity)

        self.has_cdn()

        print("digested")

    except Exception as e:
        # Incase some uncaught error somewhere
        if interactive or verbosity:
            print(f"An unusual exception has occurred:\n{e}")
        return 1

    # Return 0 for success
    return 0


def run_checks(
    domains: List[str],
    threads: int,
    timeout: int,
    user_agent: str,
    interactive: bool = False,
    verbose: bool = False,
    double: bool = False,
) -> Tuple[List[detectCDN.Domain], int]:
    """Orchestrate the use of DomainPot and Chef."""
    # Our domain pot
    dp = detectCDN.DomainPot(domains)

    # Our chef to manage pot
    chef = Chef(dp, threads, timeout, user_agent, interactive, verbose)

    # Run analysis for all domains
    cnt = chef.run_checks(double)

    # Return all domains in form domain_pool, count of jobs processed, error code
    return (chef.pot.domains, cnt)
