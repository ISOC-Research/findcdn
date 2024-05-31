"""detectCDN Library."""
from .cdn_check import DomainPot, cdnCheck
from .cdn_config import COMMON, CDNs, CDNs_rev
from .cdn_err import NoIPaddress

__all__ = [
    "DomainPot",
    "cdnCheck",
    "CDNs_rev",
    "CDNs",
    "COMMON",
    "NoIPaddress",
]
