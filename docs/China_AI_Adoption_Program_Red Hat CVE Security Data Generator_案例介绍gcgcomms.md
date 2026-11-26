## 案例一：Red Hat CVE Security Data Generator

**负责人：** Lv Tao

**Red Hat CVE Security Data Generator** 是面向 Red Hat Linux 基础架构运维及安全审查场景的轻量级 Python 自动化工具。基于 Red Hat Security Data API 批量获取 CVE 安全数据，并按用户配置筛选和整理 CVE 基本信息、受影响软件包、Advisory 及修复状态，最终生成结构化安全数据报告。

**主要优点**

- **安全数据检视效率：** 自动化批量 CVE 查询、筛选和报告整理。针对约 261 条 CVE、涉及多个 RHEL 版本的数据整理，传统人工方式约需 3 个工作日，目前通过工具约 3 分钟即可完成。
- **工程化（AI 辅助）：** 在 AI 协助下完成代码重构、测试用例设计和项目文档整理，将初始脚本逐步改造成结构清晰的工具项目，并通过 Git/GitHub 进行版本管理。

**主要限制**

- 当前工具主要负责 CVE 安全数据获取、筛选和报告生成，不具备实际主机漏洞扫描、补丁安装状态检查及主机合规性验证能力。
- 数据来源依赖 Red Hat Security Data API 的可用性及返回内容。

**适用人群**

- Linux / RHEL 系统运维、基础架构、信息安全及漏洞管理人员。

**成果**
- [GitHub Repository – Red Hat CVE Security Data Fetcher](https://github.com/lvtaochina/redhat_security_fetcher)


## Case 1: Red Hat CVE Security Data Generator

**Owner:** Lv Tao

**Red Hat CVE Security Data Generator** is a lightweight Python automation tool designed to support Red Hat Linux infrastructure operations and security review activities. It leverages the Red Hat Security Data API to retrieve CVE security data in batches, filter and organize CVE details based on user-defined criteria, and generate structured security data reports covering CVE information, affected packages, related advisories, and remediation status.

**Key Benefits**

- **Improved Security Data Review Efficiency:** Automates batch CVE retrieval, filtering, and report generation. For approximately 261 CVEs across multiple RHEL versions, a process that previously required around 3 working days of manual effort can now be completed in approximately 3 minutes.
- **AI-Assisted Engineering:** Leverages AI to support code refactoring, test case design, and project documentation, progressively transforming the initial script into a well-structured and maintainable utility, with Git/GitHub version control.

**Key Limitations**

- The tool focuses on CVE security data retrieval, filtering, and report generation. It does not perform host-level vulnerability scanning, installed patch status verification, or host compliance assessment.
- Data retrieval depends on the availability and response content of the Red Hat Security Data API.

**Target Users**

- Linux / RHEL system administrators, infrastructure engineers, information security professionals, and vulnerability management teams.

**Project Status**
- **Project Repository:** [Red Hat CVE Security Data Fetcher – GitHub](https://github.com/lvtaochina/redhat_security_fetcher)