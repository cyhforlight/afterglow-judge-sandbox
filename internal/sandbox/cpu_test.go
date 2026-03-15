package sandbox

import (
	"runtime"
	"strconv"
	"testing"
)

func TestPickCPU_RoundRobin(t *testing.T) {
	cpuCount := runtime.NumCPU()
	if cpuCount <= 1 {
		t.Skip("Need multiple CPUs to test round-robin")
	}

	// 收集分配的 CPU
	allocations := make([]int, cpuCount*2)
	for i := 0; i < len(allocations); i++ {
		cpuStr := pickCPU()
		cpu, err := strconv.Atoi(cpuStr)
		if err != nil {
			t.Fatalf("pickCPU returned invalid CPU: %s", cpuStr)
		}
		allocations[i] = cpu
	}

	// 验证轮询行为：检查是否覆盖了所有 CPU
	seen := make(map[int]bool)
	for i := 0; i < cpuCount; i++ {
		seen[allocations[i]] = true
	}

	// 应该看到所有 CPU（0 到 cpuCount-1）
	for i := 0; i < cpuCount; i++ {
		if !seen[i] {
			t.Errorf("CPU %d was not allocated in first %d allocations", i, cpuCount)
		}
	}

	// 验证循环：第二轮应该与第一轮相同
	for i := 0; i < cpuCount; i++ {
		first := allocations[i]
		second := allocations[cpuCount+i]
		if first != second {
			t.Errorf("Round-robin not consistent: allocations[%d]=%d, allocations[%d]=%d",
				i, first, cpuCount+i, second)
		}
	}

	t.Logf("Round-robin verified: %d CPUs, first round: %v", cpuCount, allocations[:cpuCount])
}

func TestPickCPU_SingleCore(t *testing.T) {
	// 模拟单核环境（无法真正测试，只能检查不崩溃）
	cpu := pickCPU()
	if cpu == "" {
		t.Error("pickCPU returned empty string")
	}
	t.Logf("Single core mode would return: %s", cpu)
}
