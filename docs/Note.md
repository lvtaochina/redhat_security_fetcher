# Note During development

## Implement Process 
 把你原来的基础设施/运维经验，逐渐转化成软件开发和产品交付能力
    面对一个没有标准答案的问题，我能不能自己设计出合理方案？这个能力只能通过项目积累


- | 能力                | 你完成前八项后 | 软件公司初级程序员 | 独立开发者    |
- | ----------------- | ------- | --------- | -------- |
- | Python 基础         | ✅       | ✅         | ✅        |
- | 小型脚本/工具           | ✅       | ✅         | ✅        |
- | API / JSON / 文件处理 | ✅       | ✅         | ✅        |
- | 基本工程化             | ✅       | ✅         | ✅        |
- | Git / 协作开发        | 需要加强    | 通常需要      | 基本需要     |
- | Web 前端            | 接下来学习   | 通常需要      | **需要**   |
- | 数据库               | 还需系统学习  | 通常需要      | **需要**   |
- | 完整 Web 产品         | 还没有     | 会参与       | **核心能力** |
- | 测试体系              | 基础      | 需要        | 需要       |
- | 阅读大型项目            | 较少      | 经常需要      | 经常需要     |
- | 多人协作              | 尚未充分实践  | 很重要       | 不一定      |
- | 从需求到交付            | 正在形成    | 需要        | **核心能力** |
- | 线上部署/运维           | 你的优势较明显 | 视岗位而定     | 需要       |
- | 产品设计/用户需求         | 还需积累    | 一般不是核心职责  | **非常重要** |


## 开发能力
                Python 开发能力
                       │
          ┌────────────┴────────────┐
          │                         │
      工程基础                    开发经验
          │                         │
      你正在建立                  还需要积累
          │                         │
   CLI / Testing / Logging       多个项目
   Data Model / Error            不同类型需求
   Configuration                 长期维护
   Project Structure             Debugging

顺序	层次	当前状态	主要内容
1	函数职责 / 模块划分	✅	main()、get_data()、filter_cve_data() 等职责
2	数据结构 / 类型标注	✅	RhelCveData、DataResult、泛型等
3	异常 / 错误处理	✅	DataError、DataResult、异常边界
4	配置 / 输入输出分离	✅	config.py、read_cves()
5	Logging	✅ 基本完成	Logger、Level、日志与业务输出分离
6	CLI	⏭️ 下一层	命令行参数、输入文件指定、帮助信息
7	Testing	⏭️	单元测试、边界测试、测试数据
8	Package / Project Organization	⏭️	模块拆分、目录结构、__init__.py 等
9	高级工程化	后续	retry、cache、并发、持久化等

## CODE REVIEW

### 建议的模块学习顺序
我建议不要按照文件在目录中的排列顺序，而是按照理解难度和知识关联来安排。
Module-based Learning
1. api_client.py
   
   HTTP 请求、第三方库、异常处理、Dataclass、Enum、联合类型。
   建议第一个学习
2. config.py
   
   配置管理、模块导入、Path 对象、配置与业务逻辑分离。
3. get_affected_cves.py
   
   数据结构、泛型函数、列表推导式、函数设计、程序流程、CLI、日志和文件处理。
4. tests/
   
   Unit Testing、Mock、Patch、测试隔离、测试边界和集成测试。

### Red Hat CVE 项目代码精读路线
1. Python 基础与数据组织
   
   重点文件：get_affected_cves.py
   
   学习内容：
   - 函数设计、参数与返回值
   - 字典、列表及嵌套数据结构
   - 类型注解、泛型
   - dataclass、Enum
   - List Comprehension
   目标：能够独立设计和表达业务数据结构。
2. 模块化与程序架构
   
   重点文件：api_client.py、config.py、get_affected_cves.py
   
   学习内容：
   - Module 与 Package
   - Import 机制
   - 模块职责划分
   - 函数之间的依赖关系
   - main() 的组织方式
   目标：遇到新项目时，能够规划基本目录和模块结构。
3. 异常处理与程序可靠性
   
   学习内容：
   - Python 异常体系
   - try / except / else / finally
   - 自定义错误类型
   - 异常传播与处理边界
   - 结构化成功和失败结果
   目标：能够设计有明确错误边界的程序。
4. 配置、文件和程序接口
   
   学习内容：
   - pathlib
   - 文件读写
   - argparse
   - logging
   - 虚拟环境及 requirements.txt
   目标：能够编写方便配置、运行和交付的命令行工具。
5. 测试与质量验证
   
   学习内容：
   - Unit Testing
   - Mock 与 Patch
   - TemporaryDirectory
   - StringIO
   - Integration Testing
   - 测试覆盖范围与边界条件
   目标：能够独立设计测试，而不只是运行测试。
6. Git 与项目交付
   
   学习内容：
   - Working Directory、Index、Repository
   - Commit、Branch、Remote
   - .gitignore
   - README
   - 项目依赖及交付结构
   目标：理解代码从开发、验证到交付的完整过程。

### 不要只是重新阅读，要进行问答/主动复盘
我特别建议你采用一种学习方法：每次精读一个函数或一个设计环节，完成下面五件事。

- 阅读	独立阅读原始代码
- 解释	用自己的语言解释代码做什么
- 追问	思考为什么采用这种设计
- 对照	回看测试，确认自己的理解是否正确
- 迁移	思考另一个类似场景能否复用这种方式

