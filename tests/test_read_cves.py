#!/usr/bin/env python3
from get_affected_cves import read_cves
from pathlib import Path
from tempfile import TemporaryDirectory

def test_read_cves():
    with TemporaryDirectory(dir = Path(__file__).resolve().parent) as tmp_dir:
        cves_path_normal = Path(tmp_dir) / "cves.normal.txt"
        cves_path_empty_file = Path(tmp_dir) / "cves.test.null.text"
        cves_path_with_blank_space = Path(tmp_dir) / "cves.test.blank.space.txt"

        cves_path_normal.write_text('CVE-2026-75020\nCVE-2026-74848\nCVE-2026-75005',
                                    encoding = "utf-8")
        cves_path_empty_file.write_text('', encoding = 'utf-8')
        cves_path_with_blank_space.write_text('  CVE-2026-75020\n\nCVE-2026-74848 \n  CVE-2026-75005',
                                    encoding = "utf-8")

        result_normal = read_cves(cves_path_normal)
        result_null = read_cves(cves_path_empty_file)
        result_blank_space = read_cves(cves_path_with_blank_space)

        print(f"临时目录:{tmp_dir}")
        input("按 Enter 完成检查：")

        assert result_normal == ['CVE-2026-75020', 'CVE-2026-74848', 'CVE-2026-75005']
        assert result_null == []
        assert result_blank_space == ['CVE-2026-75020', 'CVE-2026-74848', 'CVE-2026-75005']

if __name__ == "__main__":
    test_read_cves()