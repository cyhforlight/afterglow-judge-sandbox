本文件夹内存放若干代码，它们旨在测试 OJ 评测引擎能否正常编译并运行它们，同时正确评测其生成的输出是否与 Checker 对应。

每组测试用例以 `testcase-X` 的方式设立文件夹（X 是数字编号），每个文件夹内存放一个源代码文件、一对输入输出文件（data.in / data.out）。需要 SPJ 的还需要放一个 checker.cpp。

所涉及的语言有：C、C++、Java、Python3。

所涉及的 Checker 有：

* default：NOIP 比较器（忽略行末空格和回车）
* ncmp：按顺序比较 64 位整数
* rcmp6：按顺序比较浮点数，最大可接受误差（绝对误差或相对误差）不超过 10^-6
* nyesno：Zero or more yes/no, case insensitive
* wcmp：Sequence of tokens
* lcmp：Lines, ignores whitespaces
* 自定义 checker：可以自己写一两组（例如比较两个序列作为可重集合是否等价）

应该涉及的预期结果有：

* Accepted：完全一致
* Wrong Answer：答案错误（不能通过 checker）

补充：所有程序都是可以正常运行结束的，不存在 TLE / MLE / RE 等错误。

## 测试用例列表

| # | 语言 | 测试目的 | Checker | 预期结果 |
|---|------|---------|---------|----------|
| 1 | C | 简单加法计算 | default | Accepted |
| 2 | C++ | 浮点数学计算 (sin/cos/pow) | rcmp6 | Accepted |
| 3 | Java | 64位整数序列求和 | ncmp | Accepted |
| 4 | Python3 | 单词序列排序比较 | wcmp | Accepted |
| 5 | C | 多行文本输出 | lcmp | Accepted |
| 6 | C++ | Yes/No 判断 (大小写混合) | nyesno | Accepted |
| 7 | Java | 大规模浮点数组处理 | rcmp6 | Accepted |
| 8 | Python3 | 多行文本空白比较 | lcmp | Accepted |
| 9 | C | 简单加法结果错误 | default | Wrong Answer |
| 10 | C++ | 浮点精度超出误差范围 | rcmp6 | Wrong Answer |
| 11 | Java | 整数序列某项不匹配 | ncmp | Wrong Answer |
| 12 | Python3 | Token 序列顺序错误 | wcmp | Wrong Answer |
| 13 | C | 行内容但顺序不同 | lcmp | Wrong Answer |
| 14 | C++ | Yes/No 答案相反 | nyesno | Wrong Answer |
| 15 | C++ | 自定义 checker: 可重集合比较 | 自定义 | Accepted |
| 16 | Java | 自定义 checker: 数组排序验证 | 自定义 | Wrong Answer |
| 17 | C++ | 边界: 32位无符号整数回绕测试 | ncmp | Wrong Answer |
| 18 | C | 浮点边界值 (0.000002 误差) | rcmp6 | Wrong Answer |
| 19 | Java | 空输出 vs 有输出 | default | Wrong Answer |
| 20 | Python3 | 额外输出行 | lcmp | Wrong Answer |
