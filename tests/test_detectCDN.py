#!/usr/bin/env pytest -vs
"""Tests for detectCDN."""

# Third-Party Libraries
import dns.resolver

# cisagov Libraries
from findcdn.cdnEngine.detectCDN import cdnCheck, DomainPot

# Globals
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"


def test_ip():
    """Test the IP resolving feature."""
    dns.resolver.default_resolver = dns.resolver.Resolver()
    dns.resolver.default_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    dom_in = {
        "url": "dns.google.com",
        "ips": []
    }
    check = cdnCheck()
    check.ip(dom_in)

    assert "8.8.8.8" in dom_in["ips"], "the ip for dns.google.com should be 8.8.8.8"


def test_broken_ip():
    """Test a non-working domain IP resolving feature."""
    dns.resolver.default_resolver = dns.resolver.Resolver()
    dns.resolver.default_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    dom_in = {
        "url": "notarealdomain.fakedomaindne.com",
        "ips": []
    }
    check = cdnCheck()
    return_code = check.ip(dom_in)
    assert return_code != 0, "This fake site should return a non 0 code."


def test_cname():
    """Test the CNAME resolving feature."""
    dom_in = {
        "url": "www.asu.edu",
        "ips": [],
        "cnames": []
    }
    check = cdnCheck()
    check.cname(dom_in, timeout=TIMEOUT)

    assert (
        "pantheon-systems.map.fastly.net." in dom_in["cnames"]
    ), "www.asu.edu should have pantheon-systems.map.fastly.net. as a cname"


def test_broken_cname():
    """Test a non-working domain CNAME resolving feature."""
    dom_in = {
        "url": "notarealdomain.fakedomaindne.com",
        "ips": [],
        "cnames": []
    }
    check = cdnCheck()
    return_code = check.cname(dom_in, timeout=TIMEOUT)
    assert return_code != 0, "This fake site should return a non 0 code."


def test_https_lookup():
    """Test the header resolving feature."""
    dom_in = {
        "url": "google.com",
        "ips": [],
        "headers": []
    }
    check = cdnCheck()
    check.https_lookup(
        dom_in, timeout=TIMEOUT, agent=USER_AGENT, verbose=False
    )

    assert "gws" in dom_in["headers"], "google.com should have gws as a header"


def test_broken_https_lookup():
    """Test a non-working domain header resolving feature."""
    dom_in = {
        "url": "notarealdomain.fakedomaindne.com",
        "ips": [],
        "headers": []
    }
    check = cdnCheck()
    check.https_lookup(
        dom_in, timeout=TIMEOUT, agent=USER_AGENT, verbose=False
    )
    assert len(dom_in["headers"]) <= 0, "There should be no response."


def test_whois():
    """Test the whois resolving feature."""
    pot = DomainPot(["google.com"])
    check = cdnCheck()
    check.ip_whois_bulk_lookup(pot, verbose=False)
    
    assert (
        "GOOGLE, US" in pot.domains[0]["cymru_whois"]
    ), "google.com should return GOOGLE, US in the whois_data"


def test_broken_whois():
    """Test a non-working domain whois resolving feature."""
    pot = DomainPot(["notarealdomain.fakedomaindne.com"])
    check = cdnCheck()
    return_code = check.ip_whois_bulk_lookup(pot, verbose=False)
    assert return_code != 0, "This fake site should return a non 0 code."
