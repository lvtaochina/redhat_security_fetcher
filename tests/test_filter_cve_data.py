#! /usr/bin/env python3

from get_affected_cves import filter_cve_data

from config import WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS

d1 = {
  "threat_severity" : "Important",
  "public_date" : "2026-06-09T07:22:25Z",
  "bugzilla" : {
    "description" : "DBI: DBI: Buffer overflow in error handling can lead to arbitrary code execution",
    "id" : "2486734",
    "url" : "https://bugzilla.redhat.com/show_bug.cgi?id=2486734"
  },
  "cvss3" : {
    "cvss3_base_score" : "8.2",
    "cvss3_scoring_vector" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
    "status" : "verified"
  },
  "cwe" : "CWE-120",
  "details" : [ "DBI versions before 1.648 for Perl saved errors in a limited-sized buffer.\nError messages that were returned when RaiseError, PrintError or HandleError were set were written to a 200-byte buffer without a length limit.\nAttackers that can influence the error text in an application can trigger a buffer overflow.", "A flaw was found in DBI, a Perl database interface. This vulnerability allows an attacker to trigger a buffer overflow by manipulating error messages within an application. When specific error handling options are active, an attacker can provide oversized error text, which may lead to arbitrary code execution or a denial of service (DoS)." ],
  "statement" : "Exploitation of this vulnerability requires that an attacker can provide values to an endpoint using perl-DBI which trigger certain errors. The attacker has no means of directly controlling the location and thus consequences of the buffer overflow, making the most likely outcome a denial-of-service due to corruption of the application's memory.",
  "affected_release" : [ {
    "product_name" : "Red Hat Enterprise Linux 10",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38513",
    "cpe" : "cpe:/o:redhat:enterprise_linux:10.2",
    "package" : "perl-DBI-0:1.643-26.el10_2.1"
  }, {
    "product_name" : "Red Hat Enterprise Linux 8",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38901",
    "cpe" : "cpe:/a:redhat:enterprise_linux:8",
    "package" : "perl-DBI:1.641-8100020260624081239.69ef70f8"
  }, {
    "product_name" : "Red Hat Enterprise Linux 8",
    "release_date" : "2026-09-02T00:00:00Z",
    "advisory" : "RHSA-2026:62667",
    "cpe" : "cpe:/o:redhat:enterprise_linux:8",
    "package" : "perl-DBI-0:1.641-2.el8_10"
  }, {
    "product_name" : "Red Hat Enterprise Linux 9",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38512",
    "cpe" : "cpe:/a:redhat:enterprise_linux:9",
    "package" : "perl-DBI-0:1.643-9.el9_8.1"
  }, {
    "product_name" : "Red Hat Insights proxy 1.5",
    "release_date" : "2026-08-11T00:00:00Z",
    "advisory" : "RHSA-2026:53371",
    "cpe" : "cpe:/a:redhat:insights_proxy:1.5::el9",
    "package" : "insights-proxy/insights-proxy-container-rhel9:1786433656"
  } ],
  "package_state" : [ {
    "product_name" : "Red Hat Enterprise Linux 6",
    "fix_state" : "Out of support scope",
    "package_name" : "perl-DBI",
    "cpe" : "cpe:/o:redhat:enterprise_linux:6"
  }, {
    "product_name" : "Red Hat Enterprise Linux 7",
    "fix_state" : "Affected",
    "package_name" : "perl-DBI",
    "cpe" : "cpe:/o:redhat:enterprise_linux:7"
  } ],
  "references" : [ "https://www.cve.org/CVERecord?id=CVE-2026-9698\nhttps://nvd.nist.gov/vuln/detail/CVE-2026-9698\nhttps://github.com/perl5-dbi/dbi/commit/bfe5d73c162d2d1f761a639a0aa33aad6a9eb54e.patch\nhttps://metacpan.org/release/HMBRAND/DBI-1.648/changes" ],
  "name" : "CVE-2026-9698",
  "mitigation" : {
    "value" : "Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base, or stability. Users are advised to identify network-accessible applications which use perl-DBI and ensure that only trusted users have access to those applications.",
    "lang" : "en:us"
  },
  "csaw" : False
}

d2 = {
  "threat_severity" : "Important",
  "public_date" : "2026-06-09T07:22:25Z",
  "bugzilla" : {
    "description" : "DBI: DBI: Buffer overflow in error handling can lead to arbitrary code execution",
    "id" : "2486734",
    "url" : "https://bugzilla.redhat.com/show_bug.cgi?id=2486734"
  },
  "cvss3" : {
    "cvss3_base_score" : "8.2",
    "cvss3_scoring_vector" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
    "status" : "verified"
  },
  "cwe" : "CWE-120",
  "details" : [ "DBI versions before 1.648 for Perl saved errors in a limited-sized buffer.\nError messages that were returned when RaiseError, PrintError or HandleError were set were written to a 200-byte buffer without a length limit.\nAttackers that can influence the error text in an application can trigger a buffer overflow.", "A flaw was found in DBI, a Perl database interface. This vulnerability allows an attacker to trigger a buffer overflow by manipulating error messages within an application. When specific error handling options are active, an attacker can provide oversized error text, which may lead to arbitrary code execution or a denial of service (DoS)." ],
  "statement" : "Exploitation of this vulnerability requires that an attacker can provide values to an endpoint using perl-DBI which trigger certain errors. The attacker has no means of directly controlling the location and thus consequences of the buffer overflow, making the most likely outcome a denial-of-service due to corruption of the application's memory.",
  "affected_release" : [ {
    "product_name" : "Red Hat Enterprise Linux 10",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38513",
    "cpe" : "cpe:/o:redhat:enterprise_linux:10.2",
    "package" : "perl-DBI-0:1.643-26.el10_2.1"
  }, {
    "product_name" : "Red Hat Enterprise Linux 8",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38901",
    "cpe" : "cpe:/a:redhat:enterprise_linux:8",
    "package" : "perl-DBI:1.641-8100020260624081239.69ef70f8"
  }, {
    "product_name" : "Red Hat Enterprise Linux 8",
    "release_date" : "2026-09-02T00:00:00Z",
    "advisory" : "RHSA-2026:62667",
    "cpe" : "cpe:/o:redhat:enterprise_linux:8",
    "package" : "perl-DBI-0:1.641-2.el8_10"
  }, {
    "product_name" : "Red Hat Enterprise Linux 9",
    "release_date" : "2026-07-13T00:00:00Z",
    "advisory" : "RHSA-2026:38512",
    "cpe" : "cpe:/a:redhat:enterprise_linux:9",
    "package" : "perl-DBI-0:1.643-9.el9_8.1"
  }, {
    "product_name" : "Red Hat Insights proxy 1.5",
    "release_date" : "2026-08-11T00:00:00Z",
    "advisory" : "RHSA-2026:53371",
    "cpe" : "cpe:/a:redhat:insights_proxy:1.5::el9",
    "package" : "insights-proxy/insights-proxy-container-rhel9:1786433656"
  } ],
  "references" : [ "https://www.cve.org/CVERecord?id=CVE-2026-9698\nhttps://nvd.nist.gov/vuln/detail/CVE-2026-9698\nhttps://github.com/perl5-dbi/dbi/commit/bfe5d73c162d2d1f761a639a0aa33aad6a9eb54e.patch\nhttps://metacpan.org/release/HMBRAND/DBI-1.648/changes" ],
  "name" : "CVE-2026-9698",
  "mitigation" : {
    "value" : "Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base, or stability. Users are advised to identify network-accessible applications which use perl-DBI and ensure that only trusted users have access to those applications.",
    "lang" : "en:us"
  },
  "csaw" : False
}

d3 = {
  "threat_severity" : "Important",
  "public_date" : "2026-06-09T07:22:25Z",
  "bugzilla" : {
    "description" : "DBI: DBI: Buffer overflow in error handling can lead to arbitrary code execution",
    "id" : "2486734",
    "url" : "https://bugzilla.redhat.com/show_bug.cgi?id=2486734"
  },
  "cvss3" : {
    "cvss3_base_score" : "8.2",
    "cvss3_scoring_vector" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
    "status" : "verified"
  },
  "cwe" : "CWE-120",
  "details" : [ "DBI versions before 1.648 for Perl saved errors in a limited-sized buffer.\nError messages that were returned when RaiseError, PrintError or HandleError were set were written to a 200-byte buffer without a length limit.\nAttackers that can influence the error text in an application can trigger a buffer overflow.", "A flaw was found in DBI, a Perl database interface. This vulnerability allows an attacker to trigger a buffer overflow by manipulating error messages within an application. When specific error handling options are active, an attacker can provide oversized error text, which may lead to arbitrary code execution or a denial of service (DoS)." ],
  "statement" : "Exploitation of this vulnerability requires that an attacker can provide values to an endpoint using perl-DBI which trigger certain errors. The attacker has no means of directly controlling the location and thus consequences of the buffer overflow, making the most likely outcome a denial-of-service due to corruption of the application's memory.",
  "package_state" : [ {
    "product_name" : "Red Hat Enterprise Linux 6",
    "fix_state" : "Out of support scope",
    "package_name" : "perl-DBI",
    "cpe" : "cpe:/o:redhat:enterprise_linux:6"
  }, {
    "product_name" : "Red Hat Enterprise Linux 7",
    "fix_state" : "Affected",
    "package_name" : "perl-DBI",
    "cpe" : "cpe:/o:redhat:enterprise_linux:7"
  } ],
  "references" : [ "https://www.cve.org/CVERecord?id=CVE-2026-9698\nhttps://nvd.nist.gov/vuln/detail/CVE-2026-9698\nhttps://github.com/perl5-dbi/dbi/commit/bfe5d73c162d2d1f761a639a0aa33aad6a9eb54e.patch\nhttps://metacpan.org/release/HMBRAND/DBI-1.648/changes" ],
  "name" : "CVE-2026-9698",
  "mitigation" : {
    "value" : "Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base, or stability. Users are advised to identify network-accessible applications which use perl-DBI and ensure that only trusted users have access to those applications.",
    "lang" : "en:us"
  },
  "csaw" : False
}

def filter_cve_data_test_d1(d:dict) -> None:
    rhel_cve_data = filter_cve_data(d,WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS)
    assert rhel_cve_data.cve_name == "CVE-2026-9698"
    assert rhel_cve_data.public_date == "2026-06-09"
    assert rhel_cve_data.threat_severity == "Important"
    assert rhel_cve_data.affected_releases == \
        {"Red Hat Enterprise Linux 8": \
         [["perl-DBI:1.641-8100020260624081239.69ef70f8", "RHSA-2026:38901"], \
         ["perl-DBI-0:1.641-2.el8_10", "RHSA-2026:62667"]]
         }
    assert rhel_cve_data.package_states == \
        {"Red Hat Enterprise Linux 7": \
         [
            ["perl-DBI", "Affected"] \
         ]
        }

def filter_cve_data_test_d2(d:dict) -> None:
    rhel_cve_data = filter_cve_data(d,WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS)
    assert rhel_cve_data.affected_releases == \
        {"Red Hat Enterprise Linux 8": \
         [["perl-DBI:1.641-8100020260624081239.69ef70f8", "RHSA-2026:38901"], \
         ["perl-DBI-0:1.641-2.el8_10", "RHSA-2026:62667"]]
         }
    assert rhel_cve_data.package_states == {}

def filter_cve_data_test_d3(d:dict) -> None:
    rhel_cve_data = filter_cve_data(d,WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS)
    assert rhel_cve_data.affected_releases == {}
    assert rhel_cve_data.package_states == \
        {"Red Hat Enterprise Linux 7": \
         [
            ["perl-DBI", "Affected"] \
         ]
        }

def main() -> None:
    filter_cve_data_test_d1(d1)
    filter_cve_data_test_d2(d2)
    filter_cve_data_test_d3(d3)
 
if __name__ == "__main__":
    main()