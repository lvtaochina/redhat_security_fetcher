#!/usr/bin/env python3

from enum import Enum, auto
import sys
from dataclasses import dataclass
import requests
# from datetime import datetime, timedelta
from pathlib import Path

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'

PROXIES = {}

#uncomment lines below to specify proxy server
# HTTPS_PROXY = "http://yourproxy.example.com:8000"
# PROXIES = { "https" : HTTPS_PROXY }

want_rhels = {
                "Red Hat Enterprise Linux 7", 
                "Red Hat Enterprise Linux 7.3", 
                "Red Hat Enterprise Linux 7.5",
                "Red Hat Enterprise Linux 8", 
                "Red Hat Enterprise Linux 8.4", 
                "Red Hat Enterprise Linux 8.8", 
                "Red Hat Enterprise Linux 8.10",
             #   "Red Hat Enterprise Linux 9", 
             #   "Red Hat Enterprise Linux 9.6"
                }

fix_states = {
                "Affected",
                "Fix deferred",
#                "Not affected",
#                "Will not fix",
#                "Out of support scope",
                }      

affected_keys = [
                "product_name", 
                "package", 
                "advisory",
                ]

package_keys = [
                "product_name", 
                "package_name", 
                "fix_state",
                ]

class DataError(Enum):
    NO_DATA = auto()
    INVALID_JSON = auto()
    HTTP_ERROR = auto()
    REQUEST_EXCEPTION = auto()

@dataclass
class DataResult:
    data: dict | None
    error: DataError | None
    status_code: int | None


"""
get_data(endpoint: str) -> DataResult:
函数职责：从指定端点获取数据
参数：
    endpoint: str
    例如：
    "/cve/CVE-2026-1234.json"
处理(包含异常处理):
    1. 使用 requests 发起 HTTP 请求并返回数据
    2. 检查 HTTP 状态码
    3. 将响应转换为 JSON
    4. 检查返回数据是否为空
返回：
    DataResult 对象，包含：
        - data: dict | None
        - error: DataError | None
        - status_code: int | None
"""
def get_data(endpoint: str) -> DataResult:

    full_query = API_HOST + endpoint

    try:
        r = requests.get(full_query, proxies=PROXIES, timeout=20)
    except requests.RequestException:
        return DataResult(data=None, error=DataError.REQUEST_EXCEPTION, status_code=None)   

    if r.status_code != 200:
        return DataResult(data=None, error=DataError.HTTP_ERROR, status_code=r.status_code)
    
    try:
        data = r.json()
    except ValueError:
        return DataResult(data=None, error=DataError.INVALID_JSON, status_code=r.status_code)

    if not data:
        return DataResult(data=None, error=DataError.NO_DATA, status_code=r.status_code)

    return DataResult(data=data, error=None, status_code=r.status_code)


"""
add_to_dict[K, V](d: dict[K, list[V]], key: K, value: V) -> None:
函数职责：
    添加指定key/value到字典
输入：
    字典;字典的每个值是列表
    字典的键
    要添加到该键对应列表里的值
处理：
    按指定 key 将 value 添加到字典;如果key不存在则创建列表,如果 value 已存在则不重复添加
    - 不是对整个 dict 做“去重”,而是每一个key对应的value列表内部去重
返回: None
"""
def add_to_dict[K, V](d: dict[K, list[V]], key: K, value: V) -> None:
    if key not in d:
        d[key] = [value]
    elif value not in d[key]:
        d[key].append(value)


"""
filter_rhel_data(data: dict, want_rhels: set[str], fix_states: set[str], 
                    affected_want_keys: list[str], package_want_keys: list[str]) \
                    -> tuple[dict[str, list[list[str]]], 
                             dict[str, list[list[str]]]
                             ]
函数职责：
    处理一个 CVE API 响应数据，
    从中筛选指定 RHEL 版本的受影响数据。
    - 目前无需进一步抽象；两个数据来源业务含义不同，分别处理更清晰。

输入：
    一个 CVE 对应的 JSON 数据
    目标 RHEL 版本集合
    允许的修复状态集合
    期望的 affected_release 键列表
    期望的 package_state 键列表

处理：
    1. 筛选目标 RHEL 版本
    2. 处理有 FIX 的 affected_release 数据
    3. 处理无 FIX 的 package_state 数据

返回：
    包含两个字典的元组
        ├── 有 FIX 的数据
        └── 无 FIX 的数据
"""
def filter_rhel_data(data: dict, want_rhels: set[str], fix_states: set[str],
                      affected_keys: list[str], package_keys: list[str]) \
                      -> tuple[dict[str, list[list[str]]], 
                               dict[str, list[list[str]]]
                               ]:
    # Implementation for filtering RHEL data
    affected_releases = {}
    package_states = {}

    for rel in data.get("affected_release", []):
        prd_name = rel.get("product_name")
        if prd_name in want_rhels:
            rel_to_add = [ rel.get(k) for k in affected_keys[1:] ] 
            #用有修复的数据构建字典；是否已有该版本数据,没有的话添加新的键值对,有的话直接追加数据
            add_to_dict(affected_releases, prd_name, rel_to_add)

    for rel in data.get("package_state", []):
        prd_name = rel.get("product_name")
        if prd_name in want_rhels and rel.get("fix_state") in fix_states:
            rel_to_add = [ rel.get(k) for k in package_keys[1:] ]
            #用无修复的数据构建字典；是否已有该版本数据,没有的话添加新的键值对,有的话直接追加数据
            add_to_dict(package_states, prd_name, rel_to_add)

    return affected_releases, package_states


"""
print_rhel_table(d:dict[str, list[list[str]]]) -> None
    函数职责：格式化输出 RHEL 版本和对应数据
    输入: 一个包含 RHEL 版本和对应数据的字典
    处理: 格式化输出 RHEL 版本和对应数据
    返回: None
"""
def print_rhel_table(d:dict[str, list[list[str]]]) -> None:
    for rhel_ver, item_list in d.items():
        print(f"\n----{rhel_ver}----")
        print(f"{'组件':<85}{'勘误编号':<20}")
        for pkg, rhsa in item_list:
            print(f"{pkg:<85}{rhsa:<20}")


"""
read_cves()
    函数职责: 将包含“CVE ID”的文件读入list
    参数: N/A
    数据来源: input/cves.txt
    处理：逐行读取，去除空白，忽略空行
    返回: list[str]
    异常:input/cves.txt不存在 -> 异常自然传播
         cves.txt为空 -> 由main()处理
         文件打不开→相应的 OSError ->异常自然传播 
         文件编码有问题→UnicodeDecodeError ->异常自然传播
         cves.txt内容或格式非法 -> todo 
"""
def read_cves() -> list[str]:
    cves_path = Path(__file__).resolve().parent / 'input' / 'cves.txt'
    with cves_path.open('r', encoding='utf-8') as f:
        cves = [line.strip() for line in f if line.strip()]
    return cves


"""
main()
    函数职责: 主函数, 用于执行CVE数据获取和过滤逻辑
             * 未设计重试机制, 仅返回错误信息
    参数: N/A
    数据来源: input/cves.txt
    处理: 
        读取CVE数据文件
        处理相关异常
        - 文件不存在
        - 文件内容为空
        从红帽官网获取CVE完整安全数据
        过滤所需的安全数据
        展示安全数据
    暂不处理：
        文件打不开→相应的 OSError ->异常自然传播
        文件编码有问题→UnicodeDecodeError ->异常自然传播
    返回: None
"""
def main() -> None:
    try:
        cves = read_cves()
    except FileNotFoundError:
        print(f"Error: input/cves.txt not found", file=sys.stderr)
        return
    if not cves:
        print("Error: input/cves.txt is empty.", file=sys.stderr)
        return

    for cve in cves:
        print('\n'+'*' * 100)
        endpoint = '/cve/' + cve + '.json'
        result = get_data(endpoint)
    
        if result.error is not None:
            print(f"{cve}: {result.error} (HTTP status: {result.status_code})") 
            continue

        cve_data = result.data

        if cve_data.get('message') == 'Not Found' or ('package_state' not in cve_data and \
                                                  'affected_release' not in cve_data):
            print(cve + ' does not affect Red Hat software.')
            continue

        affected_releases, package_states = filter_rhel_data(cve_data, want_rhels, fix_states, affected_keys, package_keys)

        #print(cve_data.get('name', cve), "\n红帽有修复: ", affected_releases, "\n红帽无修复: ", package_states)
        print(cve_data.get('name', cve))
        print(cve_data.get('threat_severity', 'NO threat_severity FOUND'), 
              cve_data.get('public_date', 'NO public_date FOUND')[0:10])
        if affected_releases:
            print_rhel_table(affected_releases)
        else:
            print("有修复部分: 红帽相关版本产品不受影响")
        #if package_states:
        #   print_rhel_table(package_states)
        #else:
         #  print("无修复部分: 红帽相关版本产品不受影响")


if __name__ == "__main__":
    main()