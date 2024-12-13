//
// (C) Copyright 2019-2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package pbin

import (
	"context"
	"encoding/json"
	"os"

	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/common"
	"github.com/daos-stack/daos/src/control/fault"
	"github.com/daos-stack/daos/src/control/logging"
)

type (
	// Forwarder provides a common implementation of a request forwarder.
	// 提供通用的请求转发功能
	Forwarder struct {
		Disabled bool

		log      logging.Logger
		pbinName string
	}

	// ForwardableRequest is intended to be embedded into
	// request types that can be forwarded to the privileged
	// binary.
	ForwardableRequest struct {
		Forwarded bool
	}

	// ForwardChecker defines an interface for any request that
	// could have been forwarded.
	ForwardChecker interface {
		IsForwarded() bool
	}
)

// IsForwarded implements the ForwardChecker interface.
func (r ForwardableRequest) IsForwarded() bool {
	return r.Forwarded
}

// NewForwarder returns a configured *Forwarder.
func NewForwarder(log logging.Logger, pbinName string) *Forwarder {
	fwd := &Forwarder{
		log:      log,
		pbinName: pbinName,
	}

	return fwd
}

// GetBinaryName returns the name of the binary requests will be forwarded to.
// 获取请求要转发到的二进制程序名字，这里是转给daos_server_helper
func (f *Forwarder) GetBinaryName() string {
	return f.pbinName
}

// CanForward indicates whether commands can be forwarded to the forwarder's
// designated binary.
func (f *Forwarder) CanForward() bool {
	if _, err := common.FindBinary(f.GetBinaryName()); os.IsNotExist(err) {
		return false
	}

	return true
}

// SendReq is responsible for marshaling the forwarded request into a message
// that is sent to the privileged binary, then unmarshaling the response for
// the caller.
// 负责转发给又特权的 daos_server_helper
func (f *Forwarder) SendReq(method string, fwdReq interface{}, fwdRes interface{}) error {
	if fwdReq == nil {
		return errors.New("nil request")
	}
	if fwdRes == nil {
		return errors.New("nil response")
	}

	// 找daos_server_helper
	pbinPath, err := common.FindBinary(f.pbinName)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(fwdReq)
	if err != nil {
		return errors.Wrap(err, "failed to marshal forwarded request as payload")
	}

	// 构建req
	req := &Request{
		Method:  method,
		Payload: payload,
	}

	ctx := context.TODO()
	// 抓发执行cmd
	// pbinPath 为daos_server_helper
	res, err := ExecReq(ctx, f.log, pbinPath, req)
	if err != nil {
		if fault.IsFault(err) {
			return err
		}
		return errors.Wrap(err, "privileged binary execution failed")
	}

	if err := json.Unmarshal(res.Payload, fwdRes); err != nil {
		return errors.Wrap(err, "failed to unmarshal forwarded response")
	}

	return nil
}
