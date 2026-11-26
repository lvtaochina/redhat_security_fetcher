# Project Overview: Red Hat CVE Security Data Fetcher

## 1. Problem

Reviewing a large number of Red Hat CVEs across multiple RHEL product versions can be a repetitive and time-consuming operational task.

The traditional workflow involves manually looking up CVE information, checking affected RHEL versions, reviewing package states and related advisories, and consolidating the findings into a report.

For a review involving hundreds of CVEs, this process can take several working days, particularly when multiple RHEL versions need to be considered.

The objective of this project is to automate CVE security data retrieval, filtering, and report generation, reducing repetitive manual effort and improving the efficiency and consistency of security data reviews.

## 2. Scope

The project is a lightweight Python-based utility built on the Red Hat Security Data API.

Its planed capabilities include:

- **Batch CVE retrieval:** Read a list of CVE IDs from a text file and retrieve their corresponding security data through the Red Hat Security Data API.
- **Multi-version/ Package-state filtering:** Select multiple RHEL product versions and filter package information based on configurable states, such as `Affected` and `Fix deferred`.according to configurable requirements.
- **Security data extraction:** Extract CVE metadata, affected release information, package details, and related advisory references.
- **Report generation:** Consolidate the filtered results into a structured text report.

## 3. Users

The primary target users are:

- Linux / RHEL system administrators responsible for security maintenance and patch management.
- Infrastructure operations engineers supporting environments with multiple RHEL versions.
- Security operations and vulnerability management engineers who need to review and consolidate RHEL CVE information.

The utility is intended to support engineers in their security data review workflow rather than replace professional vulnerability assessment or patch management solutions.

## 4. Before / After Workflow

### Before: Manual Review
This workflow requires considerable repetitive effort and makes large-scale reviews less efficient.

### After: Automated Data Retrieval and Filtering
The automated workflow makes repeated reviews easier to execute and reduces the amount of manual data collection and consolidation.

## 5. Results

The initial implementation has demonstrated practical efficiency improvements.

- **Processing time:** A review involving approximately 261 CVE entries, which previously took around five days through the manual workflow, can now be completed in minutes.
- **Reduced manual effort:** Repetitive CVE lookups and data consolidation are automated.
- **Improved consistency:** The same filtering criteria can be applied repeatedly across different CVE lists and RHEL version combinations.

## 6. How AI helps
This Python based program will be developed iteratively with AI assistance. AI supports technical discussions, code refactoring, troubleshooting, test development, and documentation. 
While implementation decisions, code changes, and functional validation will be  reviewed and performed by myself.

## 7. Limitations

The current implementation has several limitations:

- **Sequential processing:** CVE requests are processed sequentially. Concurrent processing has not yet been implemented.
- **No automatic retries:** Failed API requests are logged, and processing continues with subsequent CVEs. Failed requests are not automatically retried.
- **Data retrieval rather than host assessment:** The utility retrieves and filters published Red Hat security data. It does not scan individual hosts or determine whether a particular server is actually vulnerable.
- **Input validation:** CVE ID format validation is currently basic, and valid input data is expected.
- **API dependency:** Results depend on the availability and content of the Red Hat Security Data API, as well as the configured filtering criteria.

The generated report should therefore be treated as a security data review aid, not as a definitive vulnerability assessment or patch compliance report.

## 8. Next Decision

The next step is to introduce the utility to relevant engineering and Red Hat communities or projects within Kyndryl, collect feedback, and identify additional operational use cases.

Potential improvements can be evaluated based on actual user requirements:

1. **Reliability and performance:** Consider automatic retries, request handling improvements, and concurrent processing when justified by workload and operational needs.
2. **Reporting enhancements:** Evaluate additional report formats and more flexible ways to present security findings.
3. **Broader applicability:** Assess whether additional Red Hat product families or security data requirements should be supported.
4. **Generality & integrability:** Consider configurable input/output paths via Linux command line, to better integrate with popular automation platform, like Ansible or Jenkins Pipeline。

---

**Project Positioning**

A lightweight, configurable Python automation utility designed to improve the efficiency of Red Hat CVE security data retrieval, filtering, and reporting across multiple RHEL versions.