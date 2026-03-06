package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	// 无参数：简单 hello world
	if len(os.Args) == 1 {
		fmt.Println("Hello from test binary")
		return
	}

	mode := os.Args[1]

	switch mode {
	case "stdin":
		// 从 stdin 读取一个数字，计算平方
		var n int
		_, err := fmt.Fscanf(os.Stdin, "%d", &n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stdin read error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(n * n)

	case "readfile":
		// 从文件读取一个数字，计算平方
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "readfile requires file path")
			os.Exit(1)
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "read file error: %v\n", err)
			os.Exit(1)
		}
		var n int
		_, err = fmt.Sscanf(string(data), "%d", &n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(n * n)

	case "tle":
		// 无限循环，触发 TLE
		for {
		}

	case "mle":
		// 分配大量内存，触发 MLE
		size := 100 * 1024 * 1024 // 100MB
		buf := make([]byte, size)
		// 确保内存被使用
		for i := range buf {
			buf[i] = byte(i % 256)
		}
		fmt.Println("allocated 100MB")

	case "ole":
		// 大量输出，触发 OLE
		for i := 0; i < 10000000; i++ {
			fmt.Print("x")
		}
		fmt.Println()

	case "re":
		// 非零退出码，触发 RE
		code := 42
		if len(os.Args) > 2 {
			var err error
			code, err = strconv.Atoi(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid exit code: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(code)

	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", mode)
		fmt.Fprintln(os.Stderr, "available modes: stdin, readfile, tle, mle, ole, re")
		os.Exit(1)
	}
}
