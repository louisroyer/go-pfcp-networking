// Copyright 2022 Louis Royer and the go-pfcp-networking contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package pfcp_networking

import (
	"fmt"
	"io"
	"log"
	"net"

	pfcprule "github.com/louisroyer/go-pfcp-networking/pfcprules"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func handleHeartbeatRequest(msg ReceivedMessage) error {
	log.Println("Received Heartbeat Request")
	res := message.NewHeartbeatResponse(msg.Sequence(), msg.Entity.RecoveryTimeStamp())
	return msg.ReplyTo(res)
}

func handleAssociationSetupRequest(msg ReceivedMessage) error {
	log.Println("Received Association Setup Request")
	m, ok := msg.Message.(*message.AssociationSetupRequest)
	if !ok {
		return fmt.Errorf("Issue with Association Setup Request")
	}
	peer, err := NewPFCPPeer(msg.Entity, m.NodeID)
	if err != nil {
		return err
	}
	association := NewPFCPAssociation(peer)
	err = msg.Entity.CreatePFCPAssociation(&association)
	if err != nil {
		return err
	}
	switch {
	case msg.Message == nil:
		return fmt.Errorf("msg is nil")
	case msg.Sequence == nil:
		return fmt.Errorf("msg.Sequence is nil")
	case msg.Entity == nil:
		return fmt.Errorf("entity is nil")
	case msg.Entity.NodeID() == nil:
		return fmt.Errorf("entity.NodeID() is nil")
	case msg.Entity.RecoveryTimeStamp() == nil:
		return fmt.Errorf("entity.RecoveryTimeStamp() is nil")
	}

	res := message.NewAssociationSetupResponse(msg.Sequence(), msg.Entity.NodeID(), ie.NewCause(ie.CauseRequestAccepted), msg.Entity.RecoveryTimeStamp())
	return msg.ReplyTo(res)
}

func handleSessionEstablishmentRequest(msg ReceivedMessage) error {
	log.Println("Received Session Establishment Request")
	m, ok := msg.Message.(*message.SessionEstablishmentRequest)
	if !ok {
		return fmt.Errorf("Issue with Session Establishment Request")
	}

	// If F-SEID is missing or malformed, SEID shall be set to 0
	var rseid uint64 = 0

	// CP F-SEID is a mandatory IE
	// The PFCP entities shall accept any new IP address allocated as part of F-SEID
	// other than the one(s) communicated in the Node ID during Association Establishment Procedure
	if m.CPFSEID == nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseMandatoryIEMissing), ie.NewOffendingIE(ie.FSEID))
		return msg.ReplyTo(res)
	}
	fseid, err := m.CPFSEID.FSEID()
	if err != nil {
		cause := ie.CauseMandatoryIEIncorrect
		if err == io.ErrUnexpectedEOF {
			cause = ie.CauseInvalidLength
		}
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(ie.FSEID))
		return msg.ReplyTo(res)
		return err
	}
	rseid = fseid.SEID

	// Sender must have established a PFCP Association with the Receiver Node
	if _, err := checkSenderAssociation(msg.Entity, msg.SenderAddr); err != nil {
		log.Println(err)
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation))
		return msg.ReplyTo(res)
	}

	// NodeID is a mandatory IE
	if m.NodeID == nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseMandatoryIEMissing), ie.NewOffendingIE(ie.NodeID))
		return msg.ReplyTo(res)
	}
	nid, err := m.NodeID.NodeID()
	if err != nil {
		cause := ie.CauseMandatoryIEIncorrect
		if err == io.ErrUnexpectedEOF {
			cause = ie.CauseInvalidLength
		}
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(ie.NodeID))
		return msg.ReplyTo(res)
	}

	// NodeID is used to define which PFCP Association is associated the PFCP Session
	// When the PFCP Association is destructed, associated PFCP Sessions are destructed as well
	// Since the NodeID can be modified with a Session Modification Request without constraint,
	// we only need to check the Association is established (it can be a different NodeID than the Sender's one).
	association, err := msg.Entity.GetPFCPAssociation(nid)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation))
		return msg.ReplyTo(res)
	}

	// CreatePDR is a Mandatory IE
	if m.CreatePDR == nil || len(m.CreatePDR) == 0 {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseMandatoryIEMissing), ie.NewOffendingIE(ie.CreatePDR))
		return msg.ReplyTo(res)
	}

	// CreateFAR is a Mandatory IE
	if m.CreateFAR == nil || len(m.CreateFAR) == 0 {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseMandatoryIEMissing), ie.NewOffendingIE(ie.CreateFAR))
		return msg.ReplyTo(res)
	}

	// create PDRs
	pdrs, err, cause, offendingie := pfcprule.NewPDRs(m.CreatePDR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}

	// create FARs
	fars, err, cause, offendingie := pfcprule.NewFARs(m.CreateFAR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}

	// create session with PDRs and FARs
	session, err := association.CreateSession(msg.Entity.GetNextRemoteSessionID(), m.CPFSEID, pdrs, fars)
	if err != nil {
		// Send cause(Rule creation/modification failure)
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseRuleCreationModificationFailure))
		return msg.ReplyTo(res)
	}

	// TODO: Create other type IEs

	// send response: session creation accepted
	res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseRequestAccepted), session.LocalFSEID())
	return msg.ReplyTo(res)
}

func handleSessionModificationRequest(msg ReceivedMessage) error {
	log.Println("Received Session Modification Request")
	_, ok := msg.Message.(*message.SessionModificationRequest)
	if !ok {
		return fmt.Errorf("Issue with Session Modification Request")
	}
	// Peer must have an association established or the message will be rejected
	if _, err := checkSenderAssociation(msg.Entity, msg.SenderAddr); err != nil {
		var rseid uint64 = 0
		log.Println(err)
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseNoEstablishedPFCPAssociation))
		return msg.ReplyTo(res)
	}

	// Find the Session by its F-SEID
	localseid := msg.SEID()
	sessions := msg.Entity.GetLocalSessions()
	if _, ok := sessions[localseid]; !ok {
		res := message.NewSessionModificationResponse(0, 0, 0, msg.Sequence(), 0, ie.NewCause(ie.CauseSessionContextNotFound))
		return msg.ReplyTo(res)
	}
	session := sessions[localseid]
	rseid, err := session.RemoteSEID()
	if err != nil {
		return err
	}

	// CP F-SEID
	// This IE shall be present if the CP function decides to change its F-SEID for the
	// PFCP session. The UP function shall use the new CP F-SEID for subsequent
	// PFCP Session related messages for this PFCP Session

	// TODO:
	res := message.NewSessionModificationResponse(0, 0, rseid, msg.Sequence(), 0, ie.NewCause(ie.CauseRequestRejected))
	return msg.ReplyTo(res)
}

func checkSenderAssociation(entity PFCPEntityInterface, senderAddr net.Addr) (*PFCPAssociation, error) {
	nid := senderAddr.(*net.UDPAddr).IP.String()
	association, err := entity.GetPFCPAssociation(nid)
	if err != nil {
		// TODO
		// association may be with a FQDN
	}
	if err == nil {
		return association, nil
	}
	return nil, fmt.Errorf("Entity with NodeID '%s' is has no active associtation", nid)
}
