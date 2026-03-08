# Checker Quick Start

## 1. checker 怎么编译

如果 `testlib.h` 和 checker 源码在当前目录：

```bash
g++ -std=c++17 -O2 checker.cpp -o checker
```

如果 `testlib.h` 不在当前目录，就加头文件所在目录：

```bash
g++ -std=c++17 -O2 checker.cpp -I/path/to/ -o checker
```

## 2. 编译出来的 checker 怎么用

`testlib` checker 的标准调用方式是：

```bash
./checker input.txt output.txt answer.txt
```

参数顺序固定：

1. `input.txt`：测试输入
2. `output.txt`：选手输出
3. `answer.txt`：标准答案

注意：

- checker 是自己按路径打开这 3 个文件
- 不是靠重定向读取 `output.txt`
- 因此 checker 进程需要对这 3 个文件有读权限

## 3. 怎么根据 checker 返回的东西判断发生了什么

运行 checker 后，你应该同时读取：

- 退出码
- checker 输出的说明文字（似乎一律从 stderr 读）

最常见的退出码可以这样理解：

- `0`：答案正确，通常对应 `AC`
- `1`：答案错误，通常对应 `WA`
- `2`：输出格式不合法，或选手输出不符合 checker 预期
- `3`：checker 自己出错，通常应视为系统错误
- `7`：部分分
