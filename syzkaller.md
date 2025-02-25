Syzkaller的运行由命令 `./bin/syz-manager -config=fuzz.cfg`来执行，故而syz-manager二进制可执行程序是分析的入手点

### syz-manager

```
manager: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-manager github.com/google/syzkaller/syz-manager
```

syzkaller下的Makefile文件中的上述命令用于编译syz-manager程序，可知源代码是syzkaller/syz-manager下的代码

```
syz-manager % tree
.
├── hub.go		<-与分布式相关
├── hub_test.go		<-分布式相关的的测试文件
├── manager.go		<-核心部分
├── snapshot.go		<-快照功能
└── stats.go		<-统计信息功能
```

这里先不管分布式相关的代码，先从核心部分manager.go文件入手

* 该文件中main函数为入口函数，经分析可知其核心函数为RunManager
  * RunManager函数会调用preloadCorpus函数
    * preloadCorpus函数会调用LoadSeeds函数来加载corpus.db和调用readInputs函数
      * readInputs函数会加载syzkaller/sys/linux/test下的种子文件
  * RunManager函数会调用fuzzerInstance函数
    * fuzzerInstance函数会调用runInstanceInner函数
      * runInstanceInner函数会调用Run函数来运行syz-executor，参数为runner
  * RunManager函数会调用Loop函数
    * Loop函数会调用runInstance函数
      * runInstance函数会调用job函数

[代码阅读批注](https://github.com/6eanut/syzkaller/commit/70cf61f3f5b48be035a907035319a55d29adae15)

### syz-executor

通过上面的分析，可以知道，syz-manager会通过ssh在虚拟机里面执行syz-executor这个二进制可执行程序，故而这是后续的分析着手点

```
mkdir -p ./bin/$(TARGETOS)_$(TARGETARCH)
$(CXX) -o ./bin/$(TARGETOS)_$(TARGETARCH)/syz-executor$(EXE) executor/executor.cc \
	$(ADDCXXFLAGS) $(CXXFLAGS) $(LDFLAGS) -DGOOS_$(TARGETOS)=1 -DGOARCH_$(TARGETARCH)=1 \
	-DHOSTGOOS_$(HOSTOS)=1 -DGIT_REVISION=\"$(REV)\"
```

syzkaller下的Makefile文件中的上述命令用于编译syz-executor程序，可知源代码是syzkaller/executor/executor.cc

```
executor % tree
.
├── _include
│   └── flatbuffers			<-高效的序列化库，广泛用于高效的数据传输和存储
├── android				<-针对安卓平台的文件
├── common.h				<-通用头文件，定义了跨平台的基本宏、常量和函数声明
├── common_bsd.h			<-针对不同操作系统或特定功能的扩展头文件
├── common_ext.h
├── common_ext_example.h
├── common_fuchsia.h
├── common_kvm_amd64.h
├── common_kvm_arm64.h
├── common_kvm_arm64_syzos.h
├── common_kvm_ppc64.h
├── common_linux.h
├── common_openbsd.h
├── common_test.h
├── common_usb.h
├── common_usb_linux.h
├── common_usb_netbsd.h
├── common_windows.h
├── common_zlib.h
├── conn.h				<-与网络连接相关的接口和数据结构
├── cover_filter.h			<-覆盖率过滤器的实现
├── embed.go
├── executor.cc				<-执行器实现文件
├── executor_bsd.h			<-针对不同操作系统的执行器头文件
├── executor_darwin.h
├── executor_fuchsia.h
├── executor_linux.h
├── executor_runner.h
├── executor_test.h
├── executor_windows.h
├── files.h				<-文件操作相关的接口和数据结构
├── gen_linux_amd64.go
├── gen_linux_ppc64le.go
├── kvm.h				<-与kvm相关的文件
├── kvm_amd64.S
├── kvm_amd64.S.h
├── kvm_gen.cc
├── kvm_ppc64le.S
├── kvm_ppc64le.S.h
├── nocover.h
├── shmem.h				<-共享内存相关的接口和数据结构，用于进程间通信
├── snapshot.h				<-快照机制相关的接口和数据结构，用于保存和恢复虚拟机状态
├── style_test.go
├── subprocess.h			<-子进程管理相关的接口和数据结构
├── test.h
└── test_linux.h
```

下面将从executor.cc的main函数入手

* main函数会根据第一个参数的值做不同的操作，因为syz-manager在执行syz-executor时给出的参数是runner，所以下面先看runner
  * runner函数位于executor_runner.h中，runner函数会实例一个Runner对象，并调用构造函数Runner
    * Runner函数会调用Proc函数
      * Proc函数会调用Start函数
        * Start函数会调用emplace函数，执行syz-executor，并传递参数exec
    * Runner函数会调用Loop函数
      * Loop函数会根据manager发来的消息，进行不同的处理，比如执行请求、信号更新、语料库分类等
        * 执行请求：调用ExecuteBinary或Execute
          * ExecuteBinary会执行二进制程序，并把执行结果返回给manager
          * Execute会执行请求，并和manager通信

[代码阅读批注](https://github.com/6eanut/syzkaller/commit/2a83b033c81962e20668f9bfab84b5eeea4939a1)

至此，syz-manager和syz-executor都会进入各自的Loop函数，等待彼此的RPC消息

---

* MachineChecked函数、setupFuzzer函数、BenchmarkFuzzer函数、TestFuzz函数调用NewFuzzer函数
  * NewFuzzer函数调用newExecQueues函数
    * newExecQueues函数调用genFuzz函数
      * 调用mutateProgRequest来对现有Prog进行变异
      * 调用genProgRequest生成全新的Prog
        * 会调用prog/generation.go中的Generate函数
          * Generate函数会调用generateCall函数
      * 最后调用randomCollide来对前面生成的Prog做处理得到碰撞测试后的Prog

---

prog下的主要文件：

* prio.go

用于计算call-to-call的优先级。对于一个系统调用对(X,Y)，优先级指的是对于包含了X的程序，如果加入了Y，程序出现新的代码覆盖的可能性。当前包含静态和动态两种算法。静态算法基于参数类型的分析，动态算法基于语料库。

* mutation.go

用于对程序进行变异。比如，将当前程序的一部分与语料库中另一个随机选择的程序的部分拼接起来，生成一个新的程序；随机去除程序中的一个call；对程序中的某个随机系统调用的参数进行变异操作等

* generation.go

用于生成一个包含指定数量的系统调用的程序，同时可以指定可选的系统调用集。

* minimization.go

用于对程序进行简化，删除无关的系统调用和对单个系统调用进行简化，并且保持等价。

---

问题1：syzkaller是怎么在每轮测试前筛选种子的

问题2：种子执行后，syzkaller怎么对他们排序
