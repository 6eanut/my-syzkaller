// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dispatcher

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
)

type Instance interface {
	io.Closer
}

type UpdateInfo func(cb func(info *Info))
type Runner[T Instance] func(ctx context.Context, inst T, updInfo UpdateInfo)
type CreateInstance[T Instance] func(int) (T, error)

// Pool[T] provides the functionality of a generic pool of instances.
// The instance is assumed to boot, be controlled by one Runner and then be re-created.
// The pool is assumed to have one default Runner (e.g. to be used for fuzzing), while a
// dynamically controlled sub-pool might be reserved for the arbitrary Runners.
type Pool[T Instance] struct {
	BootErrors chan error
	BootTime   stat.AverageValue[time.Duration]

	creator    CreateInstance[T]
	defaultJob Runner[T]
	jobs       chan Runner[T]

	// The mutex serializes ReserveForRun() and SetDefault() calls.
	mu        *sync.Mutex
	cv        *sync.Cond
	instances []*poolInstance[T]
	paused    bool
}

func NewPool[T Instance](count int, creator CreateInstance[T], def Runner[T]) *Pool[T] {
	instances := make([]*poolInstance[T], count)
	for i := 0; i < count; i++ {
		inst := &poolInstance[T]{
			job: def,
			idx: i,
		}
		inst.reset(func() {})
		instances[i] = inst
	}
	mu := new(sync.Mutex)
	return &Pool[T]{
		BootErrors: make(chan error, 16),
		creator:    creator,
		defaultJob: def,
		instances:  instances,
		jobs:       make(chan Runner[T]),
		mu:         mu,
		cv:         sync.NewCond(mu),
	}
}

// UpdateDefault forces all VMs to restart.
func (p *Pool[T]) SetDefault(def Runner[T]) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultJob = def
	p.kickDefault()
}

func (p *Pool[T]) kickDefault() {
	for _, inst := range p.instances {
		if !inst.reserved() {
			inst.free(p.defaultJob)
		}
	}
}

func (p *Pool[T]) TogglePause(paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = paused
	if paused {
		p.kickDefault()
	} else {
		p.cv.Broadcast()
	}
}

func (p *Pool[T]) waitUnpaused() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.paused {
		p.cv.Wait()
	}
}

func (p *Pool[T]) Loop(ctx context.Context) {
	// 使用 sync.WaitGroup 来跟踪所有 goroutine 的完成状态。
	// wg.Add(len(p.instances)) 增加等待计数器，确保每个实例对应的 goroutine 都能正确地通知其完成。
	var wg sync.WaitGroup
	wg.Add(len(p.instances))
	//遍历 p.instances，这是 Pool 中包含的所有实例列表。
	//对于每个实例 inst，创建一个匿名 goroutine 来运行该实例的主循环。
	// 这里使用了局部变量 inst := inst 来避免闭包问题，确保每个 goroutine 都有自己独立的实例引用
	for _, inst := range p.instances {
		inst := inst
		// 在每个 goroutine 内部，使用 for ctx.Err() == nil 循环检查上下文是否已经取消或超时。
		// 如果上下文没有错误，则继续调用 p.runInstance(ctx, inst) 执行实例的主逻辑。
		// p.runInstance(ctx, inst) 是实际执行实例工作的函数，可能包括启动虚拟机、执行测试任务、处理崩溃报告等
		go func() {
			for ctx.Err() == nil {
				p.runInstance(ctx, inst)
			}
			// 当上下文出现错误（即外部请求停止或系统关闭）时，goroutine 退出循环，
			// 并调用 wg.Done() 标记当前实例的 goroutine 已完成
			wg.Done()
		}()
	}
	// wg.Wait() 阻塞当前线程，直到所有 goroutine 都调用了 wg.Done()，即所有实例的工作都已完成
	wg.Wait()
}

func (p *Pool[T]) runInstance(ctx context.Context, inst *poolInstance[T]) {
	//确保池当前未处于暂停状态。如果有暂停信号，该调用会阻塞直到池被解暂停
	p.waitUnpaused()
	//使用 context.WithCancel 创建一个新的上下文，允许在需要时取消当前实例的执行。这有助于优雅地关闭资源
	ctx, cancel := context.WithCancel(ctx)
	// 记录日志，表示正在启动实例。
	//调用 inst.reset(cancel) 初始化实例并设置取消回调。
	//记录启动时间，并将实例状态设置为 StateBooting。
	//使用 defer 在函数结束时将实例状态恢复为 StateOffline。
	log.Logf(2, "pool: booting instance %d", inst.idx)

	inst.reset(cancel)

	start := time.Now()
	inst.status(StateBooting)
	defer inst.status(StateOffline)
	//调用 p.creator(inst.idx) 创建具体的实例对象（例如虚拟机）。
	//如果创建失败，将错误发送到 BootErrors 通道，并返回。
	//使用 defer obj.Close() 确保在函数结束时关闭实例对象，避免资源泄露
	obj, err := p.creator(inst.idx)
	if err != nil {
		p.BootErrors <- err
		return
	}
	defer obj.Close()
	//记录从启动开始到现在的耗时，并保存到 BootTime 统计中
	p.BootTime.Save(time.Since(start))
	//将实例状态更新为 StateWaiting，表示实例已准备好等待任务。
	//锁定互斥锁以安全地读取 job 和 jobChan 字段。
	//如果没有预先分配的任务 (job == nil)，则通过 select 语句等待新任务：
	//从 jobChan 或 switchToJob 通道接收新的任务。	
	//如果上下文被取消，则直接返回。
	inst.status(StateWaiting)
	// The job and jobChan fields are subject to concurrent updates.
	inst.mu.Lock()
	job, jobChan := inst.job, inst.jobChan
	inst.mu.Unlock()

	if job == nil {
		select {
		case newJob := <-jobChan:
			job = newJob
		case newJob := <-inst.switchToJob:
			job = newJob
		case <-ctx.Done():
			return
		}
	}
	// 更新实例状态为 StateRunning，表示实例现在正在执行任务。
	// 调用 job(ctx, obj, inst.updateInfo) 执行具体任务。
	// 这里的 job 是一个函数，它接收上下文、实例对象以及更新信息的回调函数作为参数
	inst.status(StateRunning)
	job(ctx, obj, inst.updateInfo)
}

// ReserveForRun specifies the size of the sub-pool for the execution of custom runners.
// The reserved instances will be booted, but the pool will not start the default runner.
// To unreserve all instances, execute ReserveForRun(0).
func (p *Pool[T]) ReserveForRun(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if count > len(p.instances) {
		panic("trying to reserve more VMs than present")
	}

	var free, reserved []*poolInstance[T]
	for _, inst := range p.instances {
		if inst.reserved() {
			reserved = append(reserved, inst)
		} else {
			free = append(free, inst)
		}
	}

	needReserve := count - len(reserved)
	for i := 0; i < needReserve; i++ {
		log.Logf(2, "pool: reserving instance %d", free[i].idx)
		free[i].reserve(p.jobs)
	}

	needFree := len(reserved) - count
	for i := 0; i < needFree; i++ {
		log.Logf(2, "pool: releasing instance %d", reserved[i].idx)
		reserved[i].free(p.defaultJob)
	}
}

// Run blocks until it has found an instance to execute job and until job has finished.
func (p *Pool[T]) Run(job Runner[T]) {
	done := make(chan struct{})
	p.jobs <- func(ctx context.Context, inst T, upd UpdateInfo) {
		job(ctx, inst, upd)
		close(done)
	}
	<-done
}

func (p *Pool[T]) Total() int {
	return len(p.instances)
}

type Info struct {
	State      InstanceState
	Status     string
	LastUpdate time.Time
	Reserved   bool

	// The optional callbacks.
	MachineInfo    func() []byte
	DetailedStatus func() []byte
}

func (p *Pool[T]) State() []Info {
	p.mu.Lock()
	defer p.mu.Unlock()

	ret := make([]Info, len(p.instances))
	for i, inst := range p.instances {
		ret[i] = inst.getInfo()
	}
	return ret
}

// poolInstance is not thread safe.
type poolInstance[T Instance] struct {
	mu   sync.Mutex
	info Info
	idx  int

	// Either job or jobChan will be set.
	job         Runner[T]
	jobChan     chan Runner[T]
	switchToJob chan Runner[T]
	stop        func()
}

type InstanceState int

const (
	StateOffline InstanceState = iota
	StateBooting
	StateWaiting
	StateRunning
)

// reset() and status() may be called concurrently to all other methods.
// Other methods themselves are serialized.
func (pi *poolInstance[T]) reset(stop func()) {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	pi.info = Info{
		State:      StateOffline,
		LastUpdate: time.Now(),
		Reserved:   pi.info.Reserved,
	}
	pi.stop = stop
	pi.switchToJob = make(chan Runner[T])
}

func (pi *poolInstance[T]) updateInfo(upd func(*Info)) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	upd(&pi.info)
	pi.info.LastUpdate = time.Now()
}

func (pi *poolInstance[T]) status(status InstanceState) {
	pi.updateInfo(func(info *Info) {
		info.State = status
	})
}

func (pi *poolInstance[T]) reserved() bool {
	return pi.jobChan != nil
}

func (pi *poolInstance[T]) getInfo() Info {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return pi.info
}

func (pi *poolInstance[T]) reserve(ch chan Runner[T]) {
	pi.mu.Lock()
	// If we don't take the lock, it's possible that instance restart would race with job/jobChan update.
	pi.stop()
	pi.jobChan = ch
	pi.job = nil
	pi.info.Reserved = true
	pi.mu.Unlock()
}

func (pi *poolInstance[T]) free(job Runner[T]) {
	pi.mu.Lock()
	if pi.job != nil {
		// A change of a default job, let's force restart the instance.
		pi.stop()
	}
	pi.job = job
	pi.jobChan = nil
	switchToJob := pi.switchToJob
	pi.info.Reserved = false
	pi.mu.Unlock()

	select {
	case switchToJob <- job:
		// Just in case the instance has been waiting.
		return
	default:
	}
}
