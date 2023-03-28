// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractor(t *testing.T) {
	// Objects used in tests.
	fsPath := "fs/"
	extProg, nfsProg, extNfsProg := []byte("ext"), []byte("nfs"), []byte("ext nfs")
	fs := &Subsystem{Name: "fs"}
	ext := &Subsystem{Name: "ext", Parents: []*Subsystem{fs}}
	nfs := &Subsystem{Name: "nfs", Parents: []*Subsystem{fs}}
	// Tests themselves.
	tests := []struct {
		name    string
		crashes []*Crash
		want    []*Subsystem
	}{
		{
			name: `Make sure it works fine with just a single path`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
			},
			want: []*Subsystem{fs},
		},
		{
			name: `Make sure a child shadows its parent`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
			},
			want: []*Subsystem{ext},
		},
		{
			name: `Reproducers hint at different subsystems`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   nfsProg,
				},
			},
			want: []*Subsystem{fs},
		},
		{
			name: `One subsystem from reproducers is irrelevant`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extNfsProg,
				},
			},
			want: []*Subsystem{ext},
		},
	}
	extractor := &Extractor{
		raw: &testRawExtractor{
			perPath: map[string][]*Subsystem{
				fsPath: {fs},
			},
			perProg: []progSubsystems{
				{extProg, []*Subsystem{ext}},
				{nfsProg, []*Subsystem{nfs}},
				{extNfsProg, []*Subsystem{ext, nfs}},
			},
		},
	}
	for _, test := range tests {
		ret := extractor.Extract(test.crashes)
		assert.ElementsMatch(t, ret, test.want, test.name)
	}
}

type testRawExtractor struct {
	perPath map[string][]*Subsystem
	perProg []progSubsystems
}

type progSubsystems struct {
	prog []byte
	ret  []*Subsystem
}

func (e *testRawExtractor) FromPath(path string) []*Subsystem {
	return e.perPath[path]
}

func (e *testRawExtractor) FromProg(progBytes []byte) []*Subsystem {
	for _, obj := range e.perProg {
		if reflect.DeepEqual(progBytes, obj.prog) {
			return obj.ret
		}
	}
	return nil
}
