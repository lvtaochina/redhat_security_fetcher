#!/usr/bin/env python3

from enum import Enum, auto
#import sys
from dataclasses import dataclass
import requests
# from datetime import datetime, timedelta
from pathlib import Path
from config import API_HOST, PROXIES, WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS, \
                   REQ_TIME_OUT, CVE_INPUT_PATH, \
                   LOG_FORMAT, LOG_FILENAME, LOG_LEVEL, LOG_FILEMODE, LOG_MAX_BYTES, BACKUP_COUNT, LOG_ENCODING
import logging

logging.basicConfig(format=LOG_FORMAT, filename=LOG_FILENAME, level=LOG_LEVEL, filemode=LOG_FILEMODE, 
                    encoding=LOG_ENCODING)

logger = logging.getLogger(__name__)

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

@dataclass 
class RhelCveData:
    cve_name: str
    threat_severity: str
    public_date: str
    affected_releases: dict[str, list[list[str]]]
    package_states: dict[str, list[list[str]]]

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
        r = requests.get(full_query, proxies=PROXIES, timeout=REQ_TIME_OUT)
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
                    -> RhelCveData:
函数职责：
    处理一个 CVE API 响应数据

输入：
    一个 CVE 对应的 JSON 数据
    目标 RHEL 版本集合
    允许的修复状态集合
    期望的键列表 -  affected_release 部分
    期望的键列表 -  package_state 部分

处理：
    1. 处理一个 CVE API 响应数据，
    2. 从中提取 CVE 基本信息，
    3. 筛选指定 RHEL 版本的相关数据
        - 处理有 FIX 的 affected_release 数据
        - 处理无 FIX 的 package_state 数据
返回：
    RhelCveData 对象，包含：
    - cve_name string
    - threat_severity string
    - public_date string
    - affected_releases dict[str, list[list[str]]]
    - package_states dict[str, list[list[str]]]
"""
def filter_cve_data(data: dict, want_rhels: set[str], fix_states: set[str],
                      affected_keys: list[str], package_keys: list[str]) \
                      -> RhelCveData:
    # Implementation for filtering RHEL data
    cve_name = data.get('name', 'Unknown CVE')
    threat_severity = data.get('threat_severity', 'Unknown Severity')
    public_date = data.get('public_date', 'Unknown Date')[0:10]
    
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

    return RhelCveData(cve_name, threat_severity, public_date, affected_releases, package_states)


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
    函数职责: 将CVE IDs读入list
    参数: 指定的CVE文件路径的配置参数
    处理：逐行读取，去除空白，忽略空行
    返回: list[str]
    异常:input/cves.txt不存在 -> 异常自然传播到主函数
         cves.txt为空 -> 无异常, 直接由main()处理
         文件打不开→相应的 OSError ->异常自然传播 
         文件编码有问题→UnicodeDecodeError ->异常自然传播
         cves.txt内容或格式非法 -> todo 
"""
def read_cves(cves_path: Path) -> list[str]:
    # cves_path = Path(__file__).resolve().parent / 'input' / 'cves.txt'
    with cves_path.open('r', encoding='utf-8') as f:
        cves = [line.strip() for line in f if line.strip()]
    return cves


"""
main()
    函数职责: 主函数, 用于执行CVE数据获取和过滤逻辑
             * 未设计重试机制, 仅返回错误信息
    参数: N/A
    数据来源: CVE_INPUT_PATH配置参数
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
        cves = read_cves(CVE_INPUT_PATH)
    except FileNotFoundError:
       # print(f"Error: {CVE_INPUT_PATH} not found", file=sys.stderr)
        logger.error(f"Error: {CVE_INPUT_PATH} not found")
        return
    if not cves:
        # print(f"Error: {CVE_INPUT_PATH} is empty.", file=sys.stderr)
        logger.error(f"Error: {CVE_INPUT_PATH} is empty.")
        return

    num_cves = len(cves)
    logger.info(f"Processing {num_cves} CVEs from {CVE_INPUT_PATH}")

    for count, cve in enumerate(cves, start=1):
        #print('\n'+'*' * 100)
        endpoint = '/cve/' + cve + '.json'
        result = get_data(endpoint)
    
        if result.error is not None:
          #  print(f"{cve}: {result.error} (HTTP status: {result.status_code})") 
          #  Todo: to be retried, but not implemented yet
            logger.info(f"{cve} ({count}/{num_cves}): {result.error} (HTTP status: {result.status_code})")
            continue

        cve_data = result.data
        
        rhel_cve_data = filter_cve_data(cve_data, WANT_RHELS, FIX_STATES, AFFECTED_KEYS, PACKAGE_KEYS)

        if not rhel_cve_data.affected_releases and not rhel_cve_data.package_states:
            # print('does not affect Red Hat software.')
            logger.warning(f"{cve} ({count}/{num_cves}): does not affect Red Hat software.")
            continue    

        print('\n'+'*' * 100)
        logger.info(f"{rhel_cve_data.cve_name} ({count}/{num_cves}) {rhel_cve_data.threat_severity} {rhel_cve_data.public_date}")
        print(rhel_cve_data.cve_name, rhel_cve_data.threat_severity, rhel_cve_data.public_date)
        if rhel_cve_data.affected_releases:
            print_rhel_table(rhel_cve_data.affected_releases)
        else:
            print("有修复部分:您所关注的RHEL版本不受影响")
        #if rhel_cve_data.package_states:
        #   print_rhel_table(rhel_cve_data.package_states)
        #else:
         #  print("无修复部分: 您所关注的RHEL版本不受影响")

if __name__ == "__main__":
    main()