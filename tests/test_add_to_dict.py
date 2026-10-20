#! /usr/bin/env python3
from get_affected_cves import add_to_dict

# 测试 1：字典为空时，添加一条数据
def test_add_to_dict_empty():
    d = {}
    add_to_dict(d, 'rhel-8', ['package2', 'RHSA-2024:5678'])
    assert d == {'rhel-8': [['package2', 'RHSA-2024:5678']]}

# 测试 2：字典中已有该版本数据，追加新数据
def test_add_to_dict_existing():
    d = {'rhel-7': [['package7', 'RHSA-2025:1234']] }
    add_to_dict(d, 'rhel-7', ['package8', 'RHSA-2025:5678'])
    assert d == {'rhel-7': [['package7', 'RHSA-2025:1234'], ['package8', 'RHSA-2025:5678']]}

# 测试 3：字典中已有该版本数据，但键值为空列表，追加新数据
def test_add_to_dict_existing_empty_list():
    d = {'rhel9': []}
    add_to_dict(d, 'rhel9', ['package9', 'RHSA-2025-1357'])
    assert d == {'rhel9': [['package9', 'RHSA-2025-1357']]}

# 测试 4：字典中已有其他版本数据，添加新版本数据
def test_add_to_dict_new_version():
    d = {'rhel-6': [['package6', 'RHSA-2026-1234']]}
    add_to_dict(d, 'rhel-5', ['package5', 'RHSA-2026-5678'])
    assert d == {
        'rhel-6': [['package6', 'RHSA-2026-1234']],
        'rhel-5': [['package5', 'RHSA-2026-5678']]
        }
       
# 测试 5：字典中已有该版本数据，追加已有数据 
def test_add_to_dict_existing_duplicate():
    d = {'rhel-8': [['package1', 'RHSA-2024:1234']]}
    add_to_dict(d, 'rhel-8', ['package1', 'RHSA-2024:1234'])
    assert d == {'rhel-8': [['package1', 'RHSA-2024:1234']]}

def main():
    test_add_to_dict_empty()
    test_add_to_dict_existing()
    test_add_to_dict_existing_empty_list()
    test_add_to_dict_new_version()
    test_add_to_dict_existing_duplicate()

if __name__ == "__main__":
    main()