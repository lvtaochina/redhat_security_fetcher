from enum import Enum, auto
from dataclasses import dataclass
import requests
from config import API_HOST, REQ_TIME_OUT, PROXIES

class DataError(Enum):
    NO_DATA = auto()
    INVALID_JSON = auto()
    HTTP_ERROR = auto()
    REQUEST_EXCEPTION = auto()


@dataclass
class DataSuccess:
    data: dict
    status_code: int


@dataclass
class DataFail:
    error: DataError
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
    DataFail 对象，包含：
        - error: DataError
        - status_code: int | None
    DataSuccess 对象，包含：
        - data: dict
        - status_code: int
"""
def get_data(endpoint: str) -> DataFail | DataSuccess:

    full_query = API_HOST + endpoint

    try:
        r = requests.get(full_query, proxies=PROXIES, timeout=REQ_TIME_OUT)
    except requests.RequestException:
    #    return DataResult(data=None, error=DataError.REQUEST_EXCEPTION, status_code=None)
        return DataFail(error=DataError.REQUEST_EXCEPTION, status_code=None)         

    if r.status_code != 200:
    #    return DataResult(data=None, error=DataError.HTTP_ERROR, status_code=r.status_code)
        return DataFail(error=DataError.HTTP_ERROR, status_code=r.status_code)
        
    try:
        data = r.json()
    except ValueError:
    #    return DataResult(data=None, error=DataError.INVALID_JSON, status_code=r.status_code)
        return DataFail(error=DataError.INVALID_JSON, status_code=r.status_code)

    if not data:
    #    return DataResult(data=None, error=DataError.NO_DATA, status_code=r.status_code)
        return DataFail(error=DataError.NO_DATA, status_code=r.status_code)

    # return DataResult(data=data, error=None, status_code=r.status_code)
    return DataSuccess(data=data, status_code=r.status_code)