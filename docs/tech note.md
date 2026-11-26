# git
## 常用命令
### Git 初始配置
* 设置提交代码时使用的用户名和邮箱。
```text
git config --global user.name "Your Name"
git config --global user.email "your_email@example.com"
```
* 查看当前配置：
```text
git config --list
```

### ssh连通性确认
```text
ssh -T git@github.com
```
* 如果连接成功，通常会显示：
```text
Hi username! You've successfully authenticated, but GitHub does not provide shell access.
```

### 获取代码库
```text
git clone git@github.com:lvtaochina/redhat_security_fetcher.git ./
```

### 查看当前工作区状态
```text
git status
git status --short   简洁状态
```

### 将当前目录下的变更加入暂存区（Stage Changes）
```text
git add .
```
* 添加指定文件或目录
```text
git add .gitignore
git add config/
```
* 将文件从暂存区移除，但保留工作区修改：
```text
git restore --staged .gitignore
```

### commit变更
* 注意：只有已经加入暂存区的变更才会被提交。
```text
git commit -m "updated: .gitignore was updated"
```

### 推送变更到 GitHub（Push）
* 将本地提交推送到远程仓库
```text
git push
```
* `将本地提交推送到远程仓库,其中 -u 用于建立本地分支与远程分支之间的跟踪关系，后续通常可以直接使用 git push`
```text
git push -u origin branch_name
```

### 回退到某个版本
```text
git checkout 0098d8b
```

### 查看版本日志
* 查看提交历史
```text
git log
```
* 简洁模式
```text
git log --oneline
```
* 查看所有分支的提交历史：
```text
git log --oneline --all
```
* 查看指定提交的详细信息：
```text
git show 0098d8b
```

### 获取远程仓库变更

* `获取远程仓库的最新提交信息，但不自动合并到当前分支`
```text
git fetch
```
* `获取远程变更并整合到当前分支`
```text
git pull
```

### 撤销工作区修改
* `撤销指定文件尚未暂存的修改，恢复到最近一次提交的状态;
注意：该操作会丢弃指定文件尚未暂存的修改，执行前确认不再需要这些内容。`
```text
git restore .gitignore
```