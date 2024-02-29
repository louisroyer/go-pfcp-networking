// Copyright 2022 Louis Royer and the go-pfcp-networking contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package pfcp_networking

import (
	"fmt"
	"io"
	"sync"

	"github.com/louisroyer/go-pfcp-networking/pfcp/api"
	"github.com/wmnsk/go-pfcp/ie"
)

type farmapInternal = map[api.FARID]api.FARInterface

type FARMap struct {
	farmap farmapInternal
	mu     sync.RWMutex
}

func (m *FARMap) Foreach(f func(api.FARInterface) error) error {
	for _, far := range m.farmap {
		err := f(far)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *FARMap) Get(key api.FARID) (api.FARInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if far, exists := m.farmap[key]; exists {
		return far, nil
	}
	return nil, fmt.Errorf("FAR %d does not exist.", key)
}

func (m *FARMap) Add(far api.FARInterface) error {
	id, err := far.ID()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.farmap[id]; exists {
		return fmt.Errorf("FAR %d already exists.", id)
	}
	m.farmap[id] = far
	return nil
}

func (m *FARMap) SimulateAdd(far api.FARInterface) error {
	id, err := far.ID()
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, exists := m.farmap[id]; exists {
		return fmt.Errorf("FAR %d already exists.", id)
	}
	return nil
}

func (m *FARMap) Update(far api.FARInterface) error {
	// XXX: instead of replacing old FAR with new one,
	// only present fields should be replaced
	id, err := far.ID()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.farmap[id]; !exists {
		return fmt.Errorf("FAR %d does not exist.", id)
	} else {
		delete(m.farmap, id)
		m.farmap[id] = far
		return nil
	}
}

func (m *FARMap) SimulateUpdate(far api.FARInterface) error {
	id, err := far.ID()
	if err != nil {
		return err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, exists := m.farmap[id]; !exists {
		return fmt.Errorf("FAR %d does not exist.", id)
	}
	return nil
}
func (m *FARMap) Remove(key api.FARID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.farmap[key]; !exists {
		return fmt.Errorf("FAR %d does not exist.", key)
	} else {
		delete(m.farmap, key)
		return nil
	}
}
func (m *FARMap) SimulateRemove(key api.FARID) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, exists := m.farmap[key]; !exists {
		return fmt.Errorf("FAR %d does not exist.", key)
	}
	return nil
}
func (m *FARMap) NewCreateFARs() []*ie.IE {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f := make([]*ie.IE, 0)
	for _, far := range m.farmap {
		f = append(f, far.NewCreateFAR())
	}
	return f
}

func NewFARMap(fars []*ie.IE) (farmap *FARMap, err error, cause uint8, offendingIE uint16) {
	f := FARMap{
		farmap: make(farmapInternal),
		mu:     sync.RWMutex{},
	}
	for _, far := range fars {
		id, err := far.FARID()
		if err != nil {
			switch err {
			case io.ErrUnexpectedEOF:
				return nil, err, ie.CauseInvalidLength, ie.FARID
			case ie.ErrIENotFound:
				return nil, err, ie.CauseMandatoryIEMissing, ie.FARID
			default:
				return nil, err, ie.CauseMandatoryIEIncorrect, ie.CreateFAR
			}
		}
		aa, err := far.ApplyAction()
		if err != nil {
			switch err {
			case io.ErrUnexpectedEOF:
				return nil, err, ie.CauseInvalidLength, ie.ApplyAction
			case ie.ErrIENotFound:
				return nil, err, ie.CauseMandatoryIEMissing, ie.ApplyAction
			default:
				return nil, err, ie.CauseMandatoryIEIncorrect, ie.CreateFAR
			}
		}

		// This IE shall be present when the Apply Action requests
		// the packets to be forwarded. It may be present otherwise.
		mustHaveFP := false
		hasFP := false
		if far.HasFORW() {
			mustHaveFP = true
		}

		fp, err := far.ForwardingParameters()

		if err != nil && mustHaveFP {
			//XXX:  workaround for a free5gc-smf bug: Forwarding Parameters are missing sometimes
			fp = make([]*ie.IE, 0)
			hasFP = true
			// Once this bug is gone, we could replace the above by:
			//if err == io.ErrUnexpectedEOF {
			//	return nil, err, ie.CauseInvalidLength, ie.ForwardingParameters
			//}
			//if ie.NewApplyAction(aa).HasFORW() && err == ie.ErrIENotFound {
			//	return nil, err, ie.CauseConditionalIEMissing, ie.ForwardingParameters
			//}
		} else if err == nil {
			hasFP = true
		}

		if !hasFP {
			err = f.Add(NewFAR(ie.NewFARID(id), ie.NewApplyAction(aa...), nil))
		} else {
			err = f.Add(NewFAR(ie.NewFARID(id), ie.NewApplyAction(aa...), ie.NewForwardingParameters(fp...)))
		}
		if err != nil {
			return nil, err, ie.CauseMandatoryIEIncorrect, ie.CreateFAR
		}
	}
	return &f, nil, 0, 0

}
