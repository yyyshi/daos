//
// (C) Copyright 2022 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package raft

type (
	// SystemDatabase contains system-level information
	// that must be raft-replicated.
	// 属性相关的 map
	SystemDatabase struct {
		Attributes map[string]string
	}
)
