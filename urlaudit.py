import socket
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlunparse
from typing import Any
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


class Colors:
    """ANSI color codes for terminal output"""

    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


class ValidationError(Exception):
    """Custom exception for validation errors"""

    pass


class ProtocolError(Exception):
    """Custom exception for protocol errors"""

    pass


class TimeoutValidationError(Exception):
    """Custom exception for timeout errors"""

    pass


class WorkersValidationError(Exception):
    """Custom exception for workers errors"""

    pass


def create_parser() -> argparse.ArgumentParser:
    "Define CLI"
    parser = argparse.ArgumentParser(
        description="Audit URL filtering categories actions quick and simple. Example python ./urlaudit_paralelo.py categories_file_path --category malware"
    )

    parser.add_argument(
        "categories_file_path",
        help="JSON file with the list of categories and URLs",
        type=str,
    )

    parser.add_argument(
        "--protocol",
        "-p",
        help="Define http, https, or both. Default is https",
        nargs="+",
        choices=["http", "https", "both"],
        type=str,
        default=[
            "https",
        ],
    )

    parser.add_argument(
        "--timeout",
        "-t",
        help="Define, in seconds, the timeout for every request. Must be a positive number. Default is 5 seconds",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--category",
        "-c",
        help="You can filter by category (malicious or non-malicious) or subcategory (every subcategory inside of the major category). E.g --category malicious (malware... phishing...) or just --category malware.",
        type=str,
        default=None,
    )

    parser.add_argument(
        "--workers",
        "-w",
        help="Number of parallel workers (threads) for concurrent requests. Default is 5. Increase for faster results.",
        type=int,
        default=5,
    )

    return parser


def validate_timeout(timeout: int) -> None:
    """
    Validate that timeout is a positive number.

    Args:
        timeout: The timeout value in seconds.

    Raises:
        TimeoutValidationError: If timeout is not a positive number.
    """
    if timeout <= 0:
        raise TimeoutValidationError(
            f"Timeout must be a positive number, got {timeout}"
        )


def validate_workers(workers: int) -> None:
    """
    Validate that workers is a positive number.

    Args:
        workers: Number of workers for ThreadPoolExecutor.

    Raises:
        WorkersValidationError: If workers is not a positive number
    """
    if workers <= 0:
        raise WorkersValidationError(
            f"Workers must be a positive number, got {workers}"
        )


def validate_url_complete(
    url: str, allowed_schemes: tuple[str, ...] = ("http", "https")
) -> bool:
    """
    Validate URL format.

    Args:
        url: URL to validate.
        allowed_schemes: Tuple of allowed schemes (e.g., ("http", "https")).

    Returns:
        True if URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)

        # 1. Check valid scheme
        if result.scheme not in allowed_schemes:
            return False

        # 2. Check has netloc (domain)
        if not result.netloc:
            return False

        # 3. Check not empty
        if not url.strip():
            return False

        # 4. Check no whitespace
        if " " in url:
            return False

        return True
    except Exception:
        return False


def validate_json_structure(json_data: Any) -> None:
    """
    Validate that json_data is a dict[str, dict[str, str]] with valid URLs.

    Args:
        json_data: The data to validate.

    Raises:
        ValidationError: If the structure is not correct.
    """
    if not isinstance(json_data, dict):
        raise ValidationError("Bad JSON format. The file must contain a dictionary.")

    for key, value in json_data.items():
        if not isinstance(key, str):
            raise ValidationError(
                f"Category key must be str, got {type(key).__name__} for key: {key}"
            )

        if not isinstance(value, dict):
            raise ValidationError(
                f"Category '{key}' must be a dict, got {type(value).__name__}"
            )

        for subcategory_key, subcategory_url in value.items():
            if not isinstance(subcategory_key, str):
                raise ValidationError(
                    f"Subcategory key under '{key}' must be str, got {type(subcategory_key).__name__}"
                )

            if not isinstance(subcategory_url, str):
                raise ValidationError(
                    f"URL value for '{key}:{subcategory_key}' must be str, got {type(subcategory_url).__name__}"
                )

            # Validate URL format
            if not validate_url_complete(subcategory_url):
                raise ValidationError(
                    f"Invalid URL format for '{key}:{subcategory_key}': {subcategory_url}"
                )


def get_categories(
    json_file_path: str, category_filter: str | None = None
) -> dict[str, str]:
    """Read category URLs from a JSON file.

    Args:
        json_file_path: Path to the JSON file containing the category URLs.
        category_filter: Filter by category or subcategory. If None, return all subcategories.

    Returns:
        Dictionary containing subcategories and their URLs.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValidationError: If the JSON structure is invalid.
        json.JSONDecodeError: If the JSON is malformed.
    """
    try:
        with open(json_file_path, mode="r", encoding="UTF-8") as file:
            json_data = json.load(file)

        validate_json_structure(json_data)

        if category_filter is None:
            categories_filter = {}
            for categories, subcategories in json_data.items():
                categories_filter.update(subcategories)
            return categories_filter

        if category_filter in json_data:
            return json_data[category_filter]

        for categories, subcategories in json_data.items():
            if category_filter in subcategories:
                return {category_filter: subcategories[category_filter]}

        raise ValidationError(f"Category [{category_filter}] not found")

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {json_file_path}")

    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            "The file is corrupted or is not valid JSON.", e.doc, e.pos
        )


def fetch_single_url(url: str, timeout: int) -> dict:
    """
    Fetch a single URL and return reason code.

    Args:
        url: URL to fetch.
        timeout: Timeout in seconds.

    Returns:
        Dictionary with reason code or "unreachable" on network error.
    """
    # It returns a dictionary so that it will be easier to return more data in the future, e.g., {time_taken: 0.5}, {headers: {...}}
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return {"reason": str(response.status)}
    except socket.timeout:
        return {"reason": "timeout"}
    except urllib.error.HTTPError as error:
        return {"reason": str(error.code)}
    except urllib.error.URLError:
        return {"reason": "unreachable"}


def change_to_http(url: str) -> str:
    """
    Change the scheme of a URL from https to http.
    """
    url_parse = urlparse(url)
    url_http = ("http",) + url_parse[1:]
    return urlunparse(url_http)


def change_to_https(url: str) -> str:
    """
    Change the scheme of a URL from http to https
    """
    url_parse = urlparse(url)
    url_https = ("https",) + url_parse[1:]
    return urlunparse(url_https)


def get_url_for_protocol(url: str, protocol: str) -> str:
    """
    Get the correct URL depending on the protocol.
    """
    if protocol == "http":
        url_for_protocol = change_to_http(url)
    else:
        url_for_protocol = change_to_https(url)

    return url_for_protocol


def evaluate_reason(status_code: str) -> str:
    """
    Evaluate the action taken by the firewall, and return "allow", "deny" or "unknown" depend of the HTTP status code.
    """
    if status_code == "200":
        return "allow"
    elif status_code == "503":
        return "deny"
    else:
        return "unknown"


def process_categories(
    url_categories: dict[str, str],
    protocols: tuple[str, ...],
    timeout: int,
    max_workers: int = 5,
) -> list[dict]:
    """Process category URLs in parallel using ThreadPoolExecutor.

    Args:
        url_categories: A dictionary mapping category names (keys) to their
            corresponding base URLs (values).
        protocols: A tuple of protocol strings (e.g., ('http', 'https'))
            to test against each category URL.
        timeout: Timeout in seconds for each request.
        max_workers: Maximum number of parallel threads (default 5).

    Returns:
        A list of dictionaries where each entry represents a category's
        evaluation for a specific protocol.
    """

    requests_info = []

    for category, url in url_categories.items():
        for protocol in protocols:
            url_for_protocol = get_url_for_protocol(url, protocol)
            requests_info.append(
                {"category": category, "protocol": protocol, "url": url_for_protocol}
            )

    # Process in parallel
    data_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        requests_futures = {
            executor.submit(fetch_single_url, request["url"], timeout): request
            for request in requests_info
        }

        for future in as_completed(requests_futures):
            request_info = requests_futures[future]
            try:
                fetch_result = future.result()
                reason = fetch_result.get("reason", "unreachable")
                action = evaluate_reason(reason)

                category_result = {
                    "category": request_info["category"],
                    "url": request_info["url"],
                    "protocol": request_info["protocol"],
                    "reason": reason,
                    "action": action,
                }

                data_results.append(category_result)

            except Exception:
                # if fails, add error result
                category_result = {
                    "category": request_info["category"],
                    "url": request_info["url"],
                    "protocol": request_info["protocol"],
                    "reason": "error",
                    "action": "unknown",
                }
                data_results.append(category_result)

    data_results.sort(key=lambda x: (x["category"], x["protocol"]))

    return data_results


def normalize_protocols(protocols: list[str]) -> tuple[str, ...]:
    """
    Normalize protocol list, expanding 'both' to ['http', 'https'].

    Args:
        protocols: List of protocol strings.

    Returns:
        Tuple of normalized protocols.

    Raises:
        ProtocolError: If invalid protocols are provided.
    """
    normalized = set()

    for protocol in protocols:
        if protocol == "both":
            normalized.add("http")
            normalized.add("https")
        elif protocol in ("http", "https"):
            normalized.add(protocol)
        else:
            raise ProtocolError(f"Invalid protocol: {protocol}")

    return tuple(sorted(normalized))


def print_results(results: list[dict]) -> None:
    """
    Print audit results to console with color formatting and perfect alignment.

    Args:
        results: List of dictionaries containing category audit results.
                Each dict should have: category, url, protocol, reason, action
    """
    if not results:
        print(f"{Colors.YELLOW}No results to display.{Colors.RESET}")
        return

    # Calculate maximum widths for alignment
    max_category_width = (
        max(len(result["category"]) for result in results) if results else 0
    )
    max_url_width = max(len(result["url"]) for result in results) if results else 0
    max_protocol_width = (
        max(len(result["protocol"]) for result in results) if results else 0
    )
    max_reason_width = (
        max(len(result["reason"]) for result in results) if results else 0
    )

    # Ensure minimum widths
    max_category_width = max(max_category_width, len("Category"))
    max_url_width = max(max_url_width, len("URL"))
    max_protocol_width = max(max_protocol_width, len("Protocol"))
    max_reason_width = max(max_reason_width, len("Reason"))

    # Print header
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*100}{Colors.RESET}")
    print(
        f"{Colors.BOLD}{Colors.CYAN}"
        f"{'Category':<{max_category_width}}  "
        f"{'Protocol':<{max_protocol_width}}  "
        f"{'Action':<8}  "
        f"{'Reason':<{max_reason_width}}  "
        f"{'URL':<{max_url_width}}"
        f"{Colors.RESET}"
    )
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*100}{Colors.RESET}")

    # Print rows
    for result in results:
        category = result["category"]
        protocol = result["protocol"]
        reason = result["reason"]
        action = result["action"]
        url = result["url"]

        # Color action based on allow/deny
        if action == "allow":
            action_colored = f"{Colors.GREEN}{action.upper():<8}{Colors.RESET}"
        elif action == "deny":
            action_colored = f"{Colors.RED}{action.upper():<8}{Colors.RESET}"
        else:
            action_colored = f"{Colors.YELLOW}{action.upper():<8}{Colors.RESET}"

        # Print row with alignment
        print(
            f"{category:<{max_category_width}}  "
            f"{protocol:<{max_protocol_width}}  "
            f"{action_colored}  "
            f"{reason:<{max_reason_width}}  "
            f"{url:<{max_url_width}}"
        )

    # Print footer
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*100}{Colors.RESET}")

    # Print summary statistics
    allow_count = sum(1 for result in results if result["action"] == "allow")
    deny_count = sum(1 for result in results if result["action"] == "deny")
    unknown_count = sum(1 for result in results if result["action"] == "unknown")

    print(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  {Colors.GREEN}✓ Allow:  {allow_count:>3}{Colors.RESET}")
    print(f"  {Colors.RED}✗ Deny:   {deny_count:>3}{Colors.RESET}")
    if unknown_count > 0:
        print(f"  {Colors.YELLOW}? Unknown: {unknown_count:>3}{Colors.RESET}")
    print(f"  {Colors.BOLD}Total:  {len(results):>3}{Colors.RESET}\n")


def main():
    parser = create_parser()
    args = parser.parse_args()

    # Validate timeout
    try:
        validate_timeout(args.timeout)
    except TimeoutValidationError as e:
        print(f"[ERROR] Timeout validation: {e}")
        return

    # Validate workers
    try:
        validate_workers(args.workers)
    except WorkersValidationError as e:
        print(f"[ERROR] Workers validation: {e}")
        return

    # Nornmalize protocols (http/https)
    try:
        protocols = normalize_protocols(args.protocol)
    except ProtocolError as e:
        print(f"[ERROR] Protocol validation: {e}")
        return

    # Laod categories from JSON file
    try:
        categories = get_categories(
            json_file_path=args.categories_file_path, category_filter=args.category
        )
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
        return
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}")
        return
    except ValidationError as e:
        print(f"[ERROR] Validation error: {e}")
        return

    # Proccess categories in parallel
    try:
        results = process_categories(
            categories,
            protocols=protocols,
            timeout=args.timeout,
            max_workers=args.workers,
        )
        print_results(results)
    except Exception as e:
        print(f"[ERROR] Unexpected error during processing: {e}")
        return


if __name__ == "__main__":
    main()
