//
// (C) Copyright 2022 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package engine

import (
	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/server/storage"
)

// LegacyStorage struct contains the old format of specifying SCM and Bdev storage.
// 包含了旧式scm 和bdev 的格式
type LegacyStorage struct {
	storage.ScmConfig  `yaml:",inline,omitempty"`
	ScmClass           storage.Class `yaml:"scm_class,omitempty"`
	storage.BdevConfig `yaml:",inline,omitempty"`
	BdevClass          storage.Class `yaml:"bdev_class,omitempty"`
}

// WasDefined returns true if the LegacyStorage reference refers to a populated struct.
func (ls *LegacyStorage) WasDefined() bool {
	return ls.ScmClass != storage.ClassNone || ls.BdevClass != storage.ClassNone
}

// WithLegacyStorage populates the engine config field appropriately.
func (ec *Config) WithLegacyStorage(lc LegacyStorage) *Config {
	ec.LegacyStorage = lc
	return ec
}

// ConvertLegacyStorage takes engine config legacy storage field and populates relevant config
// storage tiers.
// 根据最初配置的存储信息，转化成tiers
/*
// 旧格式
type LegacyStorage struct {
	storage.ScmConfig  `yaml:",inline,omitempty"`
	ScmClass           storage.Class `yaml:"scm_class,omitempty"`
	storage.BdevConfig `yaml:",inline,omitempty"`
	BdevClass          storage.Class `yaml:"bdev_class,omitempty"`
}

// 新格式（将ScmClass 和BdevClass 替换成了Tier 和Class（字符串））
// todo: class 和tier 不是描述的同一个事情吗？
type TierConfig struct {
	Tier  int        `yaml:"-"`
	Class Class      `yaml:"class"`
	Scm   ScmConfig  `yaml:",inline"`
	Bdev  BdevConfig `yaml:",inline"`
}
*/

func (ec *Config) ConvertLegacyStorage(log logging.Logger, idx int) {
	ls := ec.LegacyStorage
	if ls.WasDefined() {
		log.Noticef("engine %d: Legacy storage configuration detected. Please "+
			"migrate to new-style storage configuration.", idx)
		// 将legacy 格式的设备信息转化成 tierconfigs 格式
		var tierCfgs storage.TierConfigs
		// 1. 先处理scmclass
		if ls.ScmClass != storage.ClassNone {
			// 保存信息
			tierCfgs = append(tierCfgs,
				// 新new 一个新式结构
				storage.NewTierConfig().
					// 依次填充新new 出来的结构里的数据
					// todo: 不填充int 类型的tier 吗
					WithStorageClass(ls.ScmClass.String()).
					WithScmDeviceList(ls.ScmConfig.DeviceList...).
					WithScmMountPoint(ls.MountPoint).
					WithScmRamdiskSize(ls.RamdiskSize),
			)
		}

		// Do not add bdev tier if BdevClass is none or nvme has no devices.
		// 2. 再处理bdevclass
		bc := ls.BdevClass
		switch {
		case bc == storage.ClassNvme && ls.BdevConfig.DeviceList.Len() == 0:
			log.Debugf("legacy storage config conversion skipped for class "+
				"%s with empty bdev_list", storage.ClassNvme)
		case bc == storage.ClassNone:
			log.Debugf("legacy storage config bdev bonversion skipped for class %s",
				storage.ClassNone)
		default:
			tierCfgs = append(tierCfgs,
				storage.NewTierConfig().
					// 也没填充tier 信息
					WithStorageClass(ls.BdevClass.String()).
					WithBdevDeviceCount(ls.DeviceCount).
					WithBdevDeviceList(
						ls.BdevConfig.DeviceList.Devices()...).
					WithBdevFileSize(ls.FileSize).
					WithBdevBusidRange(
						ls.BdevConfig.BusidRange.String()),
			)
		}
		ec.WithStorage(tierCfgs...)
		ec.LegacyStorage = LegacyStorage{}
	}
}
