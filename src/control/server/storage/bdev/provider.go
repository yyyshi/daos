//
// (C) Copyright 2019-2022 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package bdev

import (
	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/server/storage"
)

var _ storage.BdevProvider = &Provider{}

type (
	// Backend defines a set of methods to be implemented by a Block Device backend.
	Backend interface {
		Prepare(storage.BdevPrepareRequest) (*storage.BdevPrepareResponse, error)
		Reset(storage.BdevPrepareRequest) (*storage.BdevPrepareResponse, error)
		Scan(storage.BdevScanRequest) (*storage.BdevScanResponse, error)
		Format(storage.BdevFormatRequest) (*storage.BdevFormatResponse, error)
		UpdateFirmware(pciAddr string, path string, slot int32) error
		WriteConfig(storage.BdevWriteConfigRequest) (*storage.BdevWriteConfigResponse, error)
	}

	// Provider encapsulates configuration and logic for interacting with a Block
	// Device Backend.
	Provider struct {
		log     logging.Logger
		backend Backend
	}
)

// DefaultProvider returns an initialized *Provider suitable for use in production code.
// 创建spdkbackend 的最外层函数：DefaultProvider
// 这个函数在不同的 package 下有不同的实现。
// 在 package scm，package bdev（当前文件），package metadata 三个包下都有各自的实现
// firmware 为固件
// todo: 所以是什么时候触发了 defaultBackend 后端的spdk 的scan 最终触发了 C.nvme_discover
func DefaultProvider(log logging.Logger) *Provider {
	// 创建默认的spdk 后端，再传递给 NewProvider
	return NewProvider(log, defaultBackend(log))
}

// NewProvider returns an initialized *Provider.
func NewProvider(log logging.Logger, backend Backend) *Provider {
	p := &Provider{
		log:     log,
		backend: backend,
	}
	return p
}

// Scan calls into the backend to discover NVMe components in the
// system.
// backend 是spdkWrapper
func (p *Provider) Scan(req storage.BdevScanRequest) (resp *storage.BdevScanResponse, err error) {
	p.log.Debug("run bdev storage provider scan")
	// func (sb *spdkBackend) Scan(
	// defaultBackend 就是backend
	// func (sb *spdkBackend) Scan(req storage.BdevScanRequest) (
	return p.backend.Scan(req)
}

// Prepare attempts to perform all actions necessary to make NVMe components
// available for use by DAOS. If Reset_ is set, rebind devices to kernel and
// reset allocation of hugepages, otherwise rebind devices to user-space
// driver compatible with SPDK and allocate hugeages.
func (p *Provider) Prepare(req storage.BdevPrepareRequest) (*storage.BdevPrepareResponse, error) {
	if req.Reset_ {
		p.log.Debug("run bdev storage provider prepare reset")
		return p.backend.Reset(req)
	}

	p.log.Debug("run bdev storage provider prepare setup")
	return p.backend.Prepare(req)
}

// Format attempts to initialize NVMe devices for use by DAOS.
// Note that this is a no-op for non-NVMe devices.
func (p *Provider) Format(req storage.BdevFormatRequest) (*storage.BdevFormatResponse, error) {
	if req.Properties.DeviceList.Len() == 0 {
		return nil, errors.New("empty DeviceList in FormatRequest")
	}

	return p.backend.Format(req)
}

// WriteConfig calls into the bdev backend to create an nvme config file.
func (p *Provider) WriteConfig(req storage.BdevWriteConfigRequest) (*storage.BdevWriteConfigResponse, error) {
	return p.backend.WriteConfig(req)
}
