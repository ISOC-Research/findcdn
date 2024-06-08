"""findcdn is a security research and reporting tool.

findcdn determine what CDN a domain has and prints or exports the results as json.

EXIT STATUS
    This utility exits with one of the following values:
    0   The list of domain's CDNs were successfully exported or printed to a file.
    >0  An error occurred.

Usage:
  findcdn file <fileIn> [options]
  findcdn list  <domain>... [options]
  findcdn (-h | --help)

Options:
  -h --help                    Show this message.
  --version                    Show the current version.
  -o FILE --output=FILE        If specified, then the JSON output file will be
                               created at the specified value.
  -v --verbose                 Includes additional print statements.
  --all                        Includes domains with and without a CDN
                               in output.
  -d --double                  Run the checks twice to increase accuracy.
  -t --threads=<thread_count>  Number of threads, otherwise use default.
  --timeout=<timeout>          Max duration in seconds to wait for a domain to
                               conclude processing, otherwise use default.
  --log_level=<log_level>      Set the log level to use, otherwise 
                               use  default
  --user_agent=<user_agent>    Set the user agent to use, otherwise
                               use default.
"""

# Standard Python Libraries
import datetime
import json
import os
import sys
from typing import Any, Dict, List
import logging

# Third-Party Libraries
import docopt
from schema import And, Or, Schema, SchemaError, Use
import validators

# Internal Libraries
from ._version import __version__
from .cdnEngine import run_checks
from .findcdn_err import FileWriteError, InvalidDomain, NoDomains, OutputFileExists, LogLevelError

# Global Variables
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
TIMEOUT = 60  # Time in seconds
THREADS = 0  # If 0 then cdnEngine uses CPU count to set thread count
LOG_LEVEL = "WARNING"  # If 0 then cdnEngine uses CPU count to set thread count

# start logging
logger = logging.getLogger(__name__)

def write_json(json_dump: str, output: str):
    """Write dict as JSON to output file."""
    try:
        with open(output, "x") as outfile:
            outfile.write(json_dump)
    except FileExistsError:
        raise OutputFileExists(output)
    except Exception as e:
        raise FileWriteError(e)


def main(
    domain_list: List[str],
    output_path: str = None,
    verbose: bool = False,
    all_domains: bool = False,
    double_in: bool = False,
    threads: int = THREADS,
    timeout: int = TIMEOUT,
    user_agent: str = USER_AGENT,
    log_level: str = LOG_LEVEL,
) -> str:
    """Take in a list of domains and determine the CDN for each return (JSON, number of successful jobs)."""

    # start and check logging
    if log_level.upper() not in ['DEBUG','INFO','WARNING','ERROR','CRITICAL']:
        raise LogLevelError(log_level)
    logging.basicConfig(level=log_level.upper())

    # Make sure the list passed is got something in it
    if len(domain_list) <= 0:
        raise NoDomains("error")

    # Validate domains in list
    for item in domain_list:
        if validators.domain(item) is not True:
            raise InvalidDomain(item)

    # Show the validated domains if in verbose mode
    if verbose:
        print("%d Domains Validated" % len(domain_list))
    logger.info("%d Domains Validated" % len(domain_list))

    # Define domain dict and counter for json
    domain_dict = {}
    CDN_count = 0

    # Check domain list
    processed_list, cnt = run_checks(
        domain_list,
        threads,
        timeout,
        user_agent,
        verbose,
        double_in,
    )

    # Parse the domain data
    for domain in processed_list:
        # Track the count of the domain has cdns
        if len(domain["cdns_by_names"]) > 0:
            CDN_count += 1

        # Setup formatting for json output
        if len(domain["cdns_by_names"]) > 0 or all_domains:
            domain_dict[domain["url"]] = {
                "ips": str(domain["ips"])[1:-1],
                "cdns": str(domain["cdns"])[1:-1],
                "cdns_by_names": str(domain["cdns_by_names"])[1:-1],
                "cnames": str(domain["cnames"])[1:-1],
                "cnames_cdns": str(domain["cnames_cdns"])[1:-1],
                "headers": str(domain["headers"])[1:-1],
                "headers_cdns": str(domain["headers_cdns"])[1:-1],
                "cymru_whois": str(domain["cymru_whois"])[1:-1],
                "cymru_whois_cdns": str(domain["cymru_whois_cdns"])[1:-1],
            }

    # Create JSON from the results and return (results, successful jobs)
    json_dict = {}
    json_dict["date"] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    json_dict["cdn_count"] = str(CDN_count)
    json_dict["domains"] = domain_dict
    json_dump = json.dumps(json_dict, indent=4, sort_keys=False)

    # Show the dump to stdout if verbose
    if verbose:
        print(json_dump)
    logger.debug("Results:\n"+json_dump)

    # Export to file if file provided
    if output_path is not None:
        write_json(json_dump, output_path)
    if verbose:
        print("Domain processing completed. %d jobs completed.\n%d domains had CDN's out of %d." % (cnt, CDN_count, len(domain_list)))
    logger.info("Domain processing completed. %d jobs completed.\n%d domains had CDN's out of %d." % (cnt, CDN_count, len(domain_list)))

    # Return json dump to callee
    return json_dump


def interactive() -> None:
    """Collect command arguments and run the main program."""
    # Obtain arguments from docopt
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Check for None params then set default if found
    if args["--user_agent"] is None:
        args["--user_agent"] = USER_AGENT
    if args["--threads"] is None:
        args["--threads"] = THREADS
    if args["--timeout"] is None:
        args["--timeout"] = TIMEOUT
    if args["--log_level"] is None:
        args["--log_level"] = LOG_LEVEL

    # Validate and convert arguments as needed with schema
    schema: Schema = Schema(
        {
            "--output": Or(
                None,
                And(
                    str,
                    lambda filename: not os.path.isfile(filename),
                    error='Output file "' + str(args["--output"]) + '" already exists!',
                ),
            ),
            "<fileIn>": Or(
                None,
                And(
                    str,
                    lambda filename: os.path.isfile(filename),
                    error='Input file "' + str(args["<fileIn>"]) + '" does not exist!',
                ),
            ),
            "--threads": And(
                Use(int),
                lambda thread_count: thread_count >= 0,
                error="Thread count must be a positive number",
            ),
            "--timeout": And(
                Use(int),
                lambda timeout: timeout > 0,
                error="The timeout duration must be a number greater than 0",
            ),
            "--user_agent": And(
                str,
                error="The user agent must be a string.",
            ),
            "--log_level": And(
                str,
                error="The log level must be 'debug', 'info', 'warning', 'error', or 'critical'.",
            ),
            "<domain>": And(list, error="Please format the domains as a list."),
            str: object,  # Don't care about other keys, if any
        }
    )
    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        logger.error("Argument error: %s" % err)
        sys.exit(1)

    # Add domains to a list
    domain_list = []
    if validated_args["file"]:
        try:
            with open(validated_args["<fileIn>"]) as f:
                domain_list = [line.rstrip() for line in f]
        except IOError as e:
            print("A file error occurred: %s" % e, file=sys.stderr)
            logger.error("A file error occurred: %s" % e)
            sys.exit(1)
    else:
        domain_list = validated_args["<domain>"]

    # Start main runner of program with supplied inputs.
    try:
        main(
            domain_list,
            validated_args["--output"],
            validated_args["--verbose"],
            validated_args["--all"],
            validated_args["--double"],
            validated_args["--threads"],
            validated_args["--timeout"],
            validated_args["--user_agent"],
            validated_args["--log_level"],
        )
    # Check for all potential exceptions
    except OutputFileExists as ofe:
        print(ofe.message)
        logger.error("Error: %s" % ofe.message)
        sys.exit(1)
    except FileWriteError as fwe:
        print(fwe.message)
        logger.error("Error: %s" % fwe.message)
        sys.exit(2)
    except InvalidDomain as invdom:
        print(invdom.message)
        logger.error("Error: %s" % invdom.message)
        sys.exit(3)
    except NoDomains as nd:
        print(nd.message)
        logger.error("Error: %s" % nd.message)
        sys.exit(4)
