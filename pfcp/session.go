// Copyright 2022 Louis Royer and the go-pfcp-networking contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package pfcp_networking

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/louisroyer/go-pfcp-networking/pfcp/api"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type PFCPSession struct {
	// isEstablished flag is used when PFCP Session Establishment Procedure has been completed
	// (can be initiated from the Local Entity or the Remote Peer, depending on kind of peer (UP/CP)
	isEstablished bool
	// association is used to send Request type PFCP Messages
	association api.PFCPAssociationInterface // XXX: use remoteFSEID to find the association from LocalEntity instead of storing an association
	// When Peer A send a message (M) to Peer B
	// M.PFCPHeader.SEID = B.LocalSEID() = A.RemoteSEID()
	// M.IPHeader.IP_DST = B.LocalIPAddress = A.RemoteIPAddress()
	localFseid  *ie.IE // local F-SEID
	remoteFseid *ie.IE // remote F-SEID, on Control Plane function this is allocated at Setup() time
	// PDR Map allow to retrieve a specific PDR by its ID
	pdr api.PDRMapInterface
	// FAR Map allow to retrieve a specific FAR by its ID
	far api.FARMapInterface
	// allows to perform atomic operations
	// This RWMutex applies on pdr, and far
	atomicMu sync.RWMutex
}

func (s *PFCPSession) RLock() {
	s.atomicMu.RLock()
}

func (s *PFCPSession) RUnlock() {
	s.atomicMu.RUnlock()
}

// Create an EstablishedPFCPSession
// Use this function when a PFCP Session Establishment Request is received (UP case),
// or when the Entity want to send a PFCP Session Establishment Request (CP case).
func newEstablishedPFCPSession(association api.PFCPAssociationInterface, fseid, rfseid *ie.IE, pdrs api.PDRMapInterface, fars api.FARMapInterface) (api.PFCPSessionInterface, error) {
	s := PFCPSession{
		isEstablished: false,
		association:   association,
		localFseid:    nil, // local F-SEID
		remoteFseid:   nil, // FSEID ie send by remote peer
		pdr:           pdrs,
		far:           fars,
		atomicMu:      sync.RWMutex{},
	}
	if fseid != nil {
		fseidFields, err := fseid.FSEID()
		s.localFseid = ie.NewFSEID(fseidFields.SEID, fseidFields.IPv4Address, fseidFields.IPv6Address)
		if err != nil {
			return nil, err
		}
	}
	if rfseid != nil {
		rfseidFields, err := rfseid.FSEID()
		s.remoteFseid = ie.NewFSEID(rfseidFields.SEID, rfseidFields.IPv4Address, rfseidFields.IPv6Address)
		if err != nil {
			return nil, err
		}
	}
	if err := s.Setup(); err != nil {
		return nil, err
	}
	// Add to SessionFSEIDMap of LocalEntity
	s.association.LocalEntity().AddEstablishedPFCPSession(&s)
	return &s, nil
}

// Get local F-SEID of this session
// This value should be used when a session related message is received.
func (s *PFCPSession) LocalFSEID() *ie.IE {
	return s.localFseid
}

// Get SEID part of local F-SEID
// This value should be used when a session related message is received.
func (s *PFCPSession) LocalSEID() (api.SEID, error) {
	fseid, err := s.localFseid.FSEID()
	if err != nil {
		return 0, err
	}
	return fseid.SEID, nil
}

// Get IP Address part of local F-SEID
// This value should be used when a session related message is received.
func (s *PFCPSession) LocalIPAddress() (net.IP, error) {
	// XXX: handle case where both HasIPv6 and HasIPv4 are set
	fseid, err := s.localFseid.FSEID()
	if err != nil {
		return nil, err
	}
	switch {
	case fseid.HasIPv6():
		return fseid.IPv6Address, nil
	case fseid.HasIPv4():
		return fseid.IPv4Address, nil
	default:
		return nil, fmt.Errorf("Local IP Address not set")
	}
}

// Get remote F-SEID of this session
// This value should be used when a session related message is send.
func (s *PFCPSession) RemoteFSEID() *ie.IE {
	return s.remoteFseid
}

// Get SEID part of remote F-SEID
// This value should be used when a session related message is send.
func (s *PFCPSession) RemoteSEID() (api.SEID, error) {
	fseid, err := s.remoteFseid.FSEID()
	if err != nil {
		return 0, err
	}
	return fseid.SEID, nil
}

// Get IP Address part of remote F-SEID
// This value should be used when a session related message is send.
func (s *PFCPSession) RemoteIPAddress() (net.IP, error) {
	// XXX: handle case where both HasIPv6 and HasIPv4 are set
	fseid, err := s.remoteFseid.FSEID()
	if err != nil {
		return nil, err
	}
	switch {
	case fseid.HasIPv6():
		return fseid.IPv6Address, nil
	case fseid.HasIPv4():
		return fseid.IPv4Address, nil
	default:
		return nil, fmt.Errorf("Remote IP Address not set")
	}
}

// Returns IDs of PDRs sorted by Precedence
// For PDI checking, the checking order is:
// look first at the first item of the array,
// look last at the last item of the array.
func (s *PFCPSession) GetSortedPDRIDs() []api.PDRID {
	// lock is not necessary, as it is to the caller to RLock and RUnlock
	return s.pdr.GetSortedPDRIDs()
}

// Get PDR associated with this PDRID
func (s *PFCPSession) GetPDR(pdrid api.PDRID) (api.PDRInterface, error) {
	// lock is not necessary, as it is to the caller to RLock and RUnlock
	return s.pdr.Get(pdrid)
}

func (s *PFCPSession) ForeachUnsortedPDR(f func(pdr api.PDRInterface) error) error {
	return s.pdr.Foreach(f)
}

// Get FAR associated with this FARID
func (s *PFCPSession) GetFAR(farid api.FARID) (api.FARInterface, error) {
	// lock is not necessary, as it is to the caller to RLock and RUnlock
	return s.far.Get(farid)
}

// Add/Update PDRs and FARs to the session
func (s *PFCPSession) AddUpdatePDRsFARs(createpdrs api.PDRMapInterface, createfars api.FARMapInterface, updatepdrs api.PDRMapInterface, updatefars api.FARMapInterface) error {
	// Transactions must be atomic to avoid having a PDR referring to a deleted FAR / not yet created FAR
	s.atomicMu.Lock()
	defer s.atomicMu.Unlock()
	// Simulate to check consistency
	// deletions

	// updates
	if err := updatepdrs.Foreach(func(pdr api.PDRInterface) error {
		return s.pdr.SimulateUpdate(pdr)
	}); err != nil {
		return err
	}
	if err := updatefars.Foreach(func(far api.FARInterface) error {
		return s.far.SimulateUpdate(far)
	}); err != nil {
		return err
	}

	// creations
	if err := createpdrs.Foreach(func(pdr api.PDRInterface) error {
		return s.pdr.SimulateAdd(pdr)
	}); err != nil {
		return err
	}
	if err := createfars.Foreach(func(far api.FARInterface) error {
		return s.far.SimulateAdd(far)
	}); err != nil {
		return err
	}
	// Performing for real
	// deletions

	// updates
	if err := updatepdrs.Foreach(func(pdr api.PDRInterface) error {
		return s.pdr.Update(pdr)
	}); err != nil {
		return err
	}
	if err := updatefars.Foreach(func(far api.FARInterface) error {
		return s.far.Update(far)
	}); err != nil {
		return err
	}

	// creations
	if err := createpdrs.Foreach(func(pdr api.PDRInterface) error {
		return s.pdr.Add(pdr)
	}); err != nil {
		return err
	}
	if err := createfars.Foreach(func(far api.FARInterface) error {
		return s.far.Add(far)
	}); err != nil {
		return err
	}

	return nil
	// TODO: if isControlPlane() -> send the Session Modification Request
}

// Set the remote FSEID of a PFCPSession
// it must be used for next session related messages
//func (s PFCPSession) SetRemoteFSEID(FSEID *ie.IE) {
//	s.remoteFseid = FSEID
//XXX: change association to the right-one (unless XXX line 26 is fixed)
//     update sessionsmap in local entity
//}

// Setup function, either by:
// performing the PFCP Session Establishment Procedure (if CP function),
// or by doing nothing particular (if UP function) since
// the PFCP Session Establishment Procedure is already performed
func (s *PFCPSession) Setup() error {
	if s.isEstablished {
		return fmt.Errorf("Session is already establihed")
	}
	switch {
	case s.association.LocalEntity().IsUserPlane():
		// Nothing more to do
		s.isEstablished = true
		return nil
	case s.association.LocalEntity().IsControlPlane():
		// Send PFCP Session Setup Request
		// first add to temporary map to avoid erroring after msg is send
		ies := make([]*ie.IE, 0)
		ies = append(ies, s.association.LocalEntity().NodeID())
		ies = append(ies, s.localFseid)
		s.pdr.Foreach(func(pdr api.PDRInterface) error {
			ies = append(ies, pdr.NewCreatePDR())
			return nil
		})
		s.far.Foreach(func(far api.FARInterface) error {
			ies = append(ies, far.NewCreateFAR())
			return nil
		})

		msg := message.NewSessionEstablishmentRequest(0, 0, 0, 0, 0, ies...)
		resp, err := s.association.Send(msg)
		if err != nil {
			return err
		}
		ser, ok := resp.(*message.SessionEstablishmentResponse)
		if !ok {
			log.Printf("got unexpected message: %s\n", resp.MessageTypeName())
		}

		remoteFseidFields, err := ser.UPFSEID.FSEID()
		if err != nil {
			return err
		}

		// update PDRs
		updatepdrs, err, cause, offendingie := NewPDRMap(ser.UpdatePDR)
		if err != nil {
			_ = cause
			_ = offendingie
			//			res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
			//			return msg.ReplyTo(res)
		}

		// update FARs
		updatefars, err, cause, offendingie := NewFARMap(ser.UpdateFAR)
		if err != nil {
			//			res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
			//			return msg.ReplyTo(res)
		}

		err = session.AddUpdatePDRsFARs(nil, nil, updatepdrs, updatefars)
		if err != nil {
			//XXX, offending IE
			//			res := message.NewSessionModificationResponse(0, 0, rseid, msg.Sequence(), 0, ie.NewCause(ie.CauseRequestRejected))
			//			return msg.ReplyTo(res)
		}

		s.remoteFseid = ie.NewFSEID(remoteFseidFields.SEID, remoteFseidFields.IPv4Address, remoteFseidFields.IPv6Address)
		s.isEstablished = true
		return nil
	default:
		return fmt.Errorf("Local PFCP entity is not a CP or a UP function")
	}
	return nil
}
