#!/usr/bin/env pytest -vs
"""Tests for cdnEngine."""

# cisagov Libraries
import findcdn.cdnEngine

# Test Global Variables
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
TIMEOUT = 30
THREADS = 0  # If 0 then cdnEngine uses CPU count to set thread count


def test_domainpot_init():
    """Test if DomainPot can be instantiated correctly."""
    domains = ["asu.edu", "login.gov", "censys.io", "realpython.com"]
    pot = findcdn.cdnEngine.detectCDN.DomainPot(domains)

    # Assertions
    for i in range(len(domains)):
        assert pot.domains[i]["url"] == domains[i], "{} is not {}".format(
            pot.domains[i]["url"], domains[i]
        )
        for j in range(len(domains)):
            if j == i:
                continue
            assert id(pot.domains[i]["cdns_by_names"]) != id(
                pot.domains[j]["cdns_by_names"]
            ), "Domain obect {} shares address with Domain object {}".format(i, j)


def test_chef_init():
    """Test if Chef can be instantiated correctly."""
    domains = ["asu.edu", "login.gov", "censys.io", "realpython.com"]
    pot = findcdn.cdnEngine.detectCDN.DomainPot(domains)
    chef = findcdn.cdnEngine.Chef([pot], len(domains), THREADS, TIMEOUT, USER_AGENT)

    # Assertions
    assert type(chef.pots) == list


def test_grab_cdn():
    """Test if Chef can obtain proper CDNs of domains."""
    domains = ["asu.edu", "login.gov", "censys.io", "realpython.com"]
    chef = findcdn.cdnEngine.Chef(domains, len(domains), THREADS, TIMEOUT, USER_AGENT)
    chef.analyze_domains()
    checked_domains = [domain for pot in chef.pots for domain in pot.domains]

    # Assertions
    assert checked_domains[0]["cdns_by_names"] == [
        "Fastly",
    ], "Did not detect {} from {}.".format(
        ['Fastly'], checked_domains[0]["url"]
    )
    assert checked_domains[1]["cdns_by_names"] == [
        'Amazon',
    ], "Did not detect {} from {}.".format(['Amazon'], checked_domains[1]["url"])
    assert checked_domains[2]["cdns_by_names"] == [
        "Cloudflare"
    ], "Did not detect {} from {}.".format(["Cloudflare"], checked_domains[2]["url"])
    assert checked_domains[3]["cdns_by_names"] == [
        "Cloudflare"
    ], "Did not detect {} from {}.".format(["Cloudflare"], checked_domains[3]["url"])


def test_has_cdn():
    """Test that of a set of domains with and without a CDN return correctly."""
    domains = ["asu.edu", "censys.io", "www.alloschool.com"]
    chef = findcdn.cdnEngine.Chef(domains, len(domains), THREADS, TIMEOUT, USER_AGENT)
    chef.analyze_domains()
    checked_domains = [domain for pot in chef.pots for domain in pot.domains]

    # Assertions
    cdn_present = 0
    for dom in checked_domains:
        if len(dom["cdns_by_names"])>0:
            cdn_present += 1

    assert cdn_present == 2, "Too many cdn_present domains counted."
    assert checked_domains[0]["url"] == "asu.edu" and checked_domains[0]["cdns_by_names"] == [
        "Fastly"
    ], (
        "Incorrect CDN detected for %s" % checked_domains[0]["url"]
    )
    assert checked_domains[1]["url"] == "censys.io" and checked_domains[1]["cdns_by_names"] == [
        "Cloudflare"
    ], ("Incorrect CDN detected for %s" % checked_domains[1]["url"])


def test_analyze_domains():
    """Test the analyze_domains orchestator works."""
    domains = ["asu.edu", "censys.io", "bannerhealth.com", "adobe.com"]
    chef = findcdn.cdnEngine.Chef(domains, len(domains), THREADS, TIMEOUT, USER_AGENT)
    chef.analyze_domains()

    # Assertions
    assert len(chef.pots) > 0, "Pot not stored correctly."


def test_run_checks_present():
    """Test the return of a list of cdn_present domains."""
    domains = ["asu.edu", "censys.io", "bannerhealth.com", "adobe.com"]
    objects, cnt = findcdn.cdnEngine.run_checks(domains, THREADS, TIMEOUT, USER_AGENT)
    cdn_present = {}
    for dom in objects:
        if len(dom["cdns_by_names"])>0:
            cdn_present[dom["url"]] = dom["cdns_by_names"]
    expected = {
        "asu.edu": ['Fastly'],
        "censys.io": ['Cloudflare'],
        "bannerhealth.com": ['Cloudflare'],
        "adobe.com": ['Akamai'],
    }

    # Assertions
    assert len(cdn_present) > 0, "Returned cdn_present list is empty."
    assert cdn_present == expected, "Returned domains do not match."
