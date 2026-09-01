# urlaudit

A simple, lightweight tool to audit URLs and check if your Palo Alto firewall URL filtering is working as espected. Test multiple URLs in parallel to quickly determine if they are allowed or blocked.

## Disclaimer

**This is a personal project and is not intended for production use.** Use at your own risk. Provides no warranty or support for this tool. Always test thoroughly in your environment before using in any critical scenario.

## Requirements

- **Python 3.9** or higher
- Standard library only (no external dependencies)

## Installation

1. Clone or download the `urlaudit.py` file to your machine.

2. Ensure Python 3.9+ is installed:
   ```bash
   python --version
   ```
  
3. (Optional) You could clone or download the 'categories.json', this file contains the test pages provided by Palo Alto to test URL filtering with all his categories. Or you can build your own categories.json

That's it! No dependencies to install.

## Quick Start

### Basic Usage

Run the tool with a JSON file containing your URLs:

```bash
python urlaudit.py categories.json
```

### Input File Format

Create a JSON file with your URL categories and subcategories. Example `categories.json`:

```json
{
  "malicious": {
    "malware": "https://example-malware.com",
    "phishing": "https://example-phishing.com"
  },
  "social-media": {
    "facebook": "https://facebook.com",
    "twitter": "https://twitter.com"
  }
}
```

**Requirements for JSON structure:**
- Top level: dictionary (category groups)
- Second level: dictionary (subcategories)
- Values: valid URLs (must start with `http://` or `https://`)

## Parameters

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `categories_file_path` | **Required.** Path to the JSON file with URL categories |

### Optional Arguments

| Short | Long | Default | Description |
|-------|------|---------|-------------|
| `-p` | `--protocol` | `https` | Protocol(s) to test: `http`, `https`, or `both` |
| `-t` | `--timeout` | `5` | Request timeout in seconds |
| `-c` | `--category` | `None` | Filter results by category or subcategory name. If not set, tests all URLs |
| `-w` | `--workers` | `5` | Number of parallel threads for concurrent requests |

## Examples

### Test all URLs with default settings (HTTPS, 5 second timeout)
```bash
python urlaudit.py categories.json
```

### Test specific category only
```bash
python urlaudit.py categories.json --category malware
```

### Test with both HTTP and HTTPS
```bash
python urlaudit.py categories.json --protocol both
```

### Increase number of workers for faster results
```bash
python urlaudit.py categories.json  --workers 10
```

### Combine multiple options
```bash
python urlaudit.py categories.json --category malicious --protocol both --timeout 10 --workers 10
```

## Output

The tool displays results in a formatted table:

```
====================================================================================================
Category            Protocol   Action    Reason                 URL
====================================================================================================
malware             https      DENY      503                    https://example-malware.com
phishing            https      DENY      503                    https://example-phishing.com
command-and-control https      ALLOW     200                    https://example-command-and-control.com
ransomware          https      ALLOW     200                    https://example-ramsomware.com
====================================================================================================

Summary:
  ✓ Allow:    2
  ✗ Deny:     2
  Total:      4
```

### Result Meanings

| Action | Reason | Meaning |
|--------|--------|---------|
| **ALLOW** | `200` | URL is accessible (HTTP 200 OK) |
| **DENY** | `503` | URL is blocked by firewall (HTTP 503) |
| **UNKNOWN** | Other/error | Unable to determine status (different HTTP code or connection error) |

## Troubleshooting

### "File not found" error
- Check that the path to your JSON file is correct
- Use absolute paths if running from different directories

### "Invalid JSON" error
- Validate your JSON file syntax using an online JSON validator
- Ensure all URLs are strings enclosed in quotes

### "Category not found" error
- Check the spelling of the category or subcategory name
- Use `-c` flag with exact category name

### "Timeout" errors
- Increase timeout value with `-t` flag (e.g., `--timeout 10`)
- Check your network connection

### Slow performance
- Increase workers with `-w` flag (e.g., `--workers 10`)
- Use `-c` to test only specific categories instead of all

## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT). Feel free to use, modify, and distribute as needed.

## Author Notes

This tool was created as a personal project for quick URL filtering audits. It uses Python's standard library for maximum portability. Contributions and feedback are welcome, but please understand this is hobby software without production guarantees.
