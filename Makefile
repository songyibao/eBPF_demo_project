# ==============================================================================
# 可扩展的 eBPF C++ 项目 Makefile
# ==============================================================================

# --- 配置区 ---
#
# 需要构建的可执行文件列表。这是主要的控制开关。
# 要添加一个新的监控程序，只需将其名称添加到此列表中。
# Makefile 会根据这些名称去寻找对应的源文件。
#
# 对于列表中的每个 'target_name'，它会假定：
#   - C++ 源文件: src/target_name.cpp
#   - BPF 源文件:  bpf/target_name.bpf.c
#
TARGETS := dns exitsnoop iosnoop

# --- 目录定义 ---
SRC_DIR := src
BPF_DIR := bpf
INCLUDE_DIR := include
OUTPUT_DIR := output
SKEL_DIR := skel

# --- 编译器与工具 ---
CXX := g++
CLANG := clang
BPFTOOL := bpftool

# --- 标志定义 ---
# C++ 编译器标志，包含了公共头文件目录和生成的骨架文件目录
CXXFLAGS := -std=c++17 -Wall -O2 -I$(INCLUDE_DIR) -I$(SKEL_DIR)
# BPF 编译器标志，包含了公共头文件目录
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR)
# 链接器标志
LDFLAGS := -l bpf -l elf

# ==============================================================================
# 构建规则 (通常无需修改以下内容)
# ==============================================================================

# --- 特殊目标: 防止 make 删除中间文件 ---
# .PRECIOUS 指令告诉 make 不要删除这些被视为“中间产物”的文件。
# 这对于保留 .skel.h 文件至关重要，以便 IDE (如 CLion) 能够持续提供代码提示和跳转功能。
# 我们同时保留 BPF object 文件，以避免不必要的骨架文件重新生成。
.PRECIOUS: $(SKEL_DIR)/%.skel.h $(OUTPUT_DIR)/%.bpf.o

# --- 构建目标 ---
# 默认的 'all' 目标会构建 TARGETS 列表中定义的所有可执行文件
.PHONY: all
all: $(patsubst %, $(OUTPUT_DIR)/%, $(TARGETS))

# --- 链接最终可执行文件的通用规则 ---
# 将 C++ object 文件链接成最终的可执行文件。
# 例如: 'make output/dns_agent'
$(OUTPUT_DIR)/%: $(OUTPUT_DIR)/%.o
	@echo "===> [链接] 正在链接最终可执行文件: $@"
	$(CXX) $< -o $@ $(LDFLAGS)

# --- 编译 C++ object 文件的通用规则 ---
# 将 C++ 源文件编译成 object 文件。
# 它依赖于对应的 BPF 骨架头文件。
# 例如: 'make output/dns_agent.o'
$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.cpp $(SKEL_DIR)/%.skel.h
	@echo "===> [编译 C++] 正在编译 C++ 源文件: $<"
	@mkdir -p $(OUTPUT_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- 生成 BPF 骨架头文件的通用规则 ---
# 从 BPF object 文件生成 C++ 骨架头文件。
# 例如: 'make skel/dns_agent.skel.h'
$(SKEL_DIR)/%.skel.h: $(OUTPUT_DIR)/%.bpf.o
	@echo "===> [生成骨架] 正在生成 eBPF 骨架文件: $@"
	@mkdir -p $(SKEL_DIR)
	$(BPFTOOL) gen skeleton $< > $@

# --- 编译 BPF object 文件的通用规则 ---
# 将 BPF C 源文件编译成 BPF object 文件。
# 例如: 'make output/dns_agent.bpf.o'
$(OUTPUT_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c
	@echo "===> [编译 BPF] 正在编译 eBPF 源文件: $<"
	@mkdir -p $(OUTPUT_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# --- 清理规则 ---
.PHONY: clean
clean:
	@echo "===> [清理] 正在移除 output 目录中的编译产物..."
	# 为了保持 IDE 功能 (如 CLion 的代码提示) 正常工作，
	# 我们特意保留 skel 目录及其中的骨架文件。
	rm -rf $(OUTPUT_DIR)