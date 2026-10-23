# Red Hat CVE Security Data Fetcher

This project retrieves CVE data through the Red Hat Security Data API, filters it according to the configured RHEL versions and package states of interest, and writes the results to a report file.

## Features

- Reads CVE IDs from a text file, one ID per line. Leading and trailing whitespace is removed, and blank lines are ignored.
- Calls the Red Hat Security Data API to retrieve JSON data for each CVE.
- Filters data according to `WANT_RHELS` and `FIX_STATES` in `config.py`.
- Extracts basic CVE information, including the CVE name, severity, publication date, affected-release package information, and package states.
- Writes results to a report file and records processing information and request failures in a log file.
- Supports command-line arguments for specifying the input file and output report path.

**Automatic retries are not currently implemented.** If a request for an individual CVE fails, the program logs a warning and continues with the remaining CVEs.

## Project Structure

```text
redhat_security_fetcher/
├── api_client.py          # Calls the Red Hat API and wraps successful/failed results
├── config.py              # API, RHEL filtering, input/output paths, logging, and other settings
├── get_affected_cves.py   # Main program, data filtering, report output, and execution flow
├── requirements.txt       # Third-party Python dependencies
├── input/                 # Local CVE input files (example file tracked by Git)
├── reports/               # Generated reports (not tracked by Git by default)
├── log/                   # Application logs (not tracked by Git by default)
├── tests/                 # Test files
└── .venv/                 # Local Python virtual environment (not tracked by Git)
```

The example input file `input/cves.example.txt` is included with the project. You can edit its CVE list or use the `--input` argument to specify your own input file. Generated reports under `reports/` and logs under `log/` are stored in their configured directories and are not tracked by Git.

## Requirements

- Python 3.12 or later. The project uses generic function syntax introduced in Python 3.12.
- Network access to the Red Hat Security Data API. If your environment requires a proxy, configure `PROXIES` in `config.py`.

## Set Up the Environment

It is recommended to use a dedicated virtual environment in the project root directory.

```bash
# Create the virtual environment
python3 -m venv .venv

# Activate the virtual environment (Linux)
source .venv/bin/activate

# Upgrade pip in the active virtual environment
python -m pip install --upgrade pip

# Install project dependencies
python -m pip install -r requirements.txt
```

To deactivate the virtual environment:

```bash
deactivate
```

`requirements.txt` declares the third-party dependencies required by the project. Python standard-library modules, such as `pathlib`, `argparse`, and `logging`, do not need to be installed separately with `pip`.

## Input File

The default input path is defined by `CVE_INPUT_PATH` in `config.py`. The current configuration uses `input/cves.example.txt`.

The input file is plain text with one CVE ID per line, for example:

```text
CVE-2026-1234
CVE-2026-5678
```

Blank lines are ignored, and leading and trailing whitespace is removed. If the input file or its parent directory does not exist, the program reports an input error. The program does not automatically create a missing input directory or generate a CVE input file.

Maintain the input file as needed. The CVE IDs above are examples only and are included to illustrate the expected format.

## Configuration

The main settings are defined in `config.py`:

| Setting | Description |
|---|---|
| `WANT_RHELS` | Set of RHEL product versions to filter; adjust as needed. |
| `CVE_INPUT_PATH` | Default CVE input file path; adjust as needed. |
| `CVE_OUTPUT_PATH` | Default report output path. |
| `API_HOST` | Base URL for the Red Hat Security Data API. |
| `PROXIES` | HTTP request proxy configuration; no proxy is configured by default. |
| `REQ_TIME_OUT` | HTTP request timeout. |
| `FIX_STATES` | Set of package states to include. |
| `AFFECTED_KEYS` | Fields to extract from `affected_release`; do not modify without updating the filtering logic. |
| `PACKAGE_KEYS` | Fields to extract from `package_state`; do not modify without updating the filtering logic. |
| `LOG_FILENAME` | Log file path. |
| `LOG_LEVEL` | Logging level. |

If you need a proxy, configure `PROXIES` for your network environment. Do not commit sensitive information, such as internal proxy credentials, to the repository.

The current implementation requires the first element of both `AFFECTED_KEYS` and `PACKAGE_KEYS` to be `product_name`. Do not change this ordering unless you also update the corresponding filtering logic.

## Run the Program

From the project root directory, with the virtual environment activated, run the program using the default paths:

```bash
./get_affected_cves.py
```

You can also specify the input and output paths using command-line arguments:

```bash
./get_affected_cves.py \
  --input /path/to/cves.txt \
  --output /path/to/report.txt
```

Argument reference:

| Argument | Short form | Description |
|---|---|---|
| `--input` | `-i` | Path to the CVE input file. Defaults to `CVE_INPUT_PATH` if omitted. |
| `--output` | `-o` | Path to the output report. Defaults to `CVE_OUTPUT_PATH` if omitted. |
| `--help` | | Displays command-line help. |

The program creates the parent directory for the output report when necessary and opens the report in write mode. An existing report at the same path may therefore be overwritten. The log directory is created by the logging initialization logic, and log messages are appended to the configured log file.

Default paths are built relative to the project configuration file. Relative paths supplied through command-line arguments are interpreted relative to the current working directory from which the program is launched. Absolute paths can be used to avoid ambiguity.

## Reports and Logs

- **Report:** The default location is defined by `CVE_OUTPUT_PATH` (usually under `reports/`). The report contains basic CVE information and RHEL release/package-state information matching the current filters.
- **Log:** The default path is defined by `LOG_FILENAME` (currently `log/rhel_cve_fetcher.log`). Logs record processing progress, cases where no records match the configured filters, and API request failures.
- **Request failures:** When a request exception occurs, the HTTP status is not 200, JSON parsing fails, or the response contains no data, `api_client.py` returns a structured failure result. The main program logs a warning and continues processing the remaining CVEs.

Note: If a CVE has no records matching the current filters, this means only that no matching records were found under the current configuration. It should not, by itself, be interpreted as proof that the CVE does not affect any Red Hat product.

## Run Tests

The test files are located in `tests/`. During development, unit tests were run for the main functions, and an end-to-end integration test using real data from the Red Hat API was completed. The tests were also rerun successfully after upgrading `requests`.

Open a terminal in the project root directory and activate the project's virtual environment before running the following commands.

- Tests for adding items to a dictionary and suppressing duplicates in `add_to_dict()`:

  ```bash
  python -m tests.test_add_to_dict
  ```

- Tests for field extraction, filtering, and handling missing fields in `filter_cve_data()`:

  ```bash
  python -m tests.test_filter_cve_data
  ```

- Tests for success, empty responses, HTTP errors, request exceptions, and JSON parsing errors in `get_data()` in `api_client.py`:

  ```bash
  python -m tests.test_get_data
  ```

- Tests for normal files, empty files, and blank lines in `read_cves()`:

  ```bash
  python -m tests.test_read_cves
  ```

- Tests for report text output from `print_rhel_table()`:

  ```bash
  python -m tests.test_print_rhel_table
  ```

## Current Limitations

- Automatic retries and concurrent processing are not implemented. In the author's development environment, processing approximately 261 CVE entries takes about 2–3 minutes.
- Results depend on the data returned by the API and on filters such as `WANT_RHELS` and `FIX_STATES`.
- CVE ID format validation is basic. Ensure that the input file contains valid CVE IDs.
- `reports/`, `log/`, and `.venv/` are managed by Git ignore rules. Do not assume that generated content, local data, or the virtual environment will be included when the repository is shared or cloned.
