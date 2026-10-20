#! /usr/bin/env python3

from get_affected_cves import print_rhel_table
from io import StringIO

def main():
    d_normal = {"Red Hat Enterprise Linux 8": [["firefox-0:140.3.0-1.el8_10", "RHSA-2025:16260"], 
                                         ["thunderbird-0:140.3.0-1.el8_10", "RHSA-2025:16589"]],
          "Red Hat Enterprise Linux 7": [["firefox", "Fix deferred"], 
                                         ]
            }
    d_empty = {}

    output_normal = StringIO()
    output_empty = StringIO()

    print_rhel_table(d_normal, file = output_normal)
    print_rhel_table(d_empty, file=output_empty)

    content_normal = output_normal.getvalue()
    content_empty = output_empty.getvalue()

    assert content_empty == ""
    # print(content_normal)
    assert "RHSA-2025:16260" in content_normal
    assert "RHSA-2025:16589" in content_normal
    assert "firefox-0:140.3.0-1.el8_10" in content_normal
    assert "thunderbird-0:140.3.0-1.el8_10" in content_normal
    assert "firefox" in content_normal
    assert "Fix deferred" in content_normal

    print(repr(content_normal))

if __name__ == "__main__":
    main()