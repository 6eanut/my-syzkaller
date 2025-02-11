// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	// 创建一个新的程序对象 p，并将其目标系统设置为 target。
	// Prog 是 syzkaller 中表示程序的核心结构体，包含一系列系统调用（Calls）及其相关信息。	
	p := &Prog{
		Target: target,
	}
	// 调用 newRand 方法创建一个随机数生成器 r，用于在生成过程中引入随机性。
	// 调用 newState 方法初始化一个状态对象 s，该对象包含生成程序时的各种上下文信息，例如：
	// 目标系统的 API 和约束条件。
	// 选择表（ChoiceTable），指导系统调用及其参数的选择。
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	// 使用循环逐步生成系统调用，直到程序中的系统调用数量达到指定的限制 ncalls。
	// 在每次迭代中：
	// 调用 r.generateCall 方法生成一组新的系统调用（可能是一个或多个）。
	// 对每个生成的系统调用 c：
	// 调用 s.analyze 分析该调用对程序状态的影响（如资源分配、依赖关系等）。
	// 将该调用添加到程序的系统调用列表 p.Calls 中。
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// 如果生成的系统调用数量超过了指定的限制 ncalls，则通过 p.RemoveCall 方法移除多余的调用。
	// 这种情况可能发生在最后生成的调用中包含了额外的资源创建操作，导致系统调用数量超出限制。
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	// 调用 p.sanitizeFix 方法对程序进行清理和修复，确保其符合语法规则和语义约束。
	// 调用 p.debugValidate 方法验证程序的正确性，确保生成的程序是有效的。
	p.sanitizeFix()
	p.debugValidate()
	return p
}
