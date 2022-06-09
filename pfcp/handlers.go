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

	"github.com/louisroyer/go-pfcp-networking/pfcp/api"
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

	if _, err := msg.Entity.NewEstablishedPFCPAssociation(m.NodeID); err != nil {
		log.Println("Rejected Association:", err)
		res := message.NewAssociationSetupResponse(msg.Sequence(), msg.Entity.NodeID(), ie.NewCause(ie.CauseRequestRejected), msg.Entity.RecoveryTimeStamp())
		return msg.ReplyTo(res)
	}

	log.Println("Association Accepted")
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
	var rseid api.SEID = 0

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
	session, err := association.CreateSession(m.CPFSEID, pdrs, fars)
	if err != nil {
		// Send cause(Rule creation/modification failure)
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseRuleCreationModificationFailure))
		return msg.ReplyTo(res)
	}
	log.Println("New Session created with local SEID: ", session.LocalSEID, " and remote SEID: ", session.RemoteSEID)

	// TODO: Create other type IEs
	// XXX: QER ie are ignored for the moment
	// send response: session creation accepted
	res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(ie.CauseRequestAccepted), session.LocalFSEID())
	return msg.ReplyTo(res)
}

func handleSessionModificationRequest(msg ReceivedMessage) error {
	log.Println("Received Session Modification Request")
	m, ok := msg.Message.(*message.SessionModificationRequest)
	if !ok {
		return fmt.Errorf("Issue with Session Modification Request")
	}
	// PFCP session related messages for sessions that are already established are sent to the IP address received
	// in the F-SEID allocated by the peer function or to the IP address of an alternative SMF in the SMF set
	// (see clause 5.22). The former IP address needs not be configured in the look up information.

	// Thereforce, use of checkSenderAssociation is prohibed when receiving Session Modification Request

	// Find the Session by its F-SEID
	ielocalnodeid := msg.Entity.NodeID()
	localnodeid, err := ielocalnodeid.NodeID()
	if err != nil {
		return err
	}
	var localip string
	switch ielocalnodeid.Payload[0] {
	case ie.NodeIDIPv4Address:
		ip4, err := net.ResolveIPAddr("ip4", localnodeid)
		if err != nil {
			return err
		}
		localip = ip4.String()
	case ie.NodeIDIPv6Address:
		ip6, err := net.ResolveIPAddr("ip6", localnodeid)
		if err != nil {
			return err
		}
		localip = ip6.String()
	case ie.NodeIDFQDN:
		ip4, _ := net.ResolveIPAddr("ip4", localnodeid)
		ip6, _ := net.ResolveIPAddr("ip6", localnodeid)
		// XXX handle localip in fseid sessions.go session_map.go when ip4 and ip6 are set
		switch {
		case ip6 != nil:
			localip = ip6.String()
		case ip4 != nil:
			localip = ip4.String()
		default:
			return fmt.Errorf("Cannot resolve NodeID")
		}
	}
	localseid := msg.SEID()
	session, err := msg.Entity.GetPFCPSession(localip, localseid)
	if err != nil {
		res := message.NewSessionModificationResponse(0, 0, 0, msg.Sequence(), 0, ie.NewCause(ie.CauseSessionContextNotFound))
		return msg.ReplyTo(res)
	}

	rseid, err := session.RemoteSEID()
	if err != nil {
		return err
	}

	//	// CP F-SEID
	//	// This IE shall be present if the CP function decides to change its F-SEID for the
	//	// PFCP session. The UP function shall use the new CP F-SEID for subsequent
	//	// PFCP Session related messages for this PFCP Session
	//
	//XXX: CP F-SEID is ignored for the moment

	// create PDRs
	createpdrs, err, cause, offendingie := pfcprule.NewPDRs(m.CreatePDR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}
	createpdrsmap := make(pfcprule.PDRMap)
	for _, pdr := range createpdrs {
		if pdr == nil {
			log.Println("A PDR is nil")
			continue
		}
		id, err := pdr.ID()
		if err != nil {
			return err
		}
		createpdrsmap[id] = pdr
	}

	// create FARs
	createfars, err, cause, offendingie := pfcprule.NewFARs(m.CreateFAR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}
	createfarsmap := make(pfcprule.FARMap)
	for _, far := range createfars {
		if far == nil {
			log.Println("A FAR is nil")
			continue
		}
		id, err := far.ID()
		if err != nil {
			return err
		}
		createfarsmap[id] = far
	}

	// update PDRs
	updatepdrs, err, cause, offendingie := pfcprule.NewPDRs(m.UpdatePDR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}
	updatepdrsmap := make(pfcprule.PDRMap)
	for _, pdr := range updatepdrs {
		if pdr == nil {
			log.Println("A PDR is nil")
			continue
		}
		id, err := pdr.ID()
		if err != nil {
			return err
		}
		updatepdrsmap[id] = pdr
	}

	// update FARs
	updatefars, err, cause, offendingie := pfcprule.NewFARs(m.UpdateFAR)
	if err != nil {
		res := message.NewSessionEstablishmentResponse(0, 0, rseid, msg.Sequence(), 0, msg.Entity.NodeID(), ie.NewCause(cause), ie.NewOffendingIE(offendingie))
		return msg.ReplyTo(res)
	}
	updatefarsmap := make(pfcprule.FARMap)
	for _, far := range updatefars {
		if far == nil {
			log.Println("A FAR is nil")
			continue
		}
		id, err := far.ID()
		if err != nil {
			return err
		}
		updatefarsmap[id] = far
	}

	err = session.AddUpdatePDRsFARs(createpdrsmap, createfarsmap, updatepdrsmap, updatefarsmap)
	if err != nil {
		//XXX, offending IE
		res := message.NewSessionModificationResponse(0, 0, rseid, msg.Sequence(), 0, ie.NewCause(ie.CauseRequestRejected))
		return msg.ReplyTo(res)
	}

	//XXX: QER modification/creation is ignored for the moment
	//XXX: Remove PDR
	//XXX: Remove FAR
	//XXX: RemoveQER

	res := message.NewSessionModificationResponse(0, 0, rseid, msg.Sequence(), 0, ie.NewCause(ie.CauseRequestAccepted))
	return msg.ReplyTo(res)
}

func checkSenderAssociation(entity api.PFCPEntityInterface, senderAddr net.Addr) (api.PFCPAssociationInterface, error) {
	// Once the PFCP Association is established, any of the IP addresses of the peer
	// function (found during the look-up) may then be used to send subsequent PFCP node related messages and PFCP
	// session establishment requests for that PFCP Association.
	nid := senderAddr.(*net.UDPAddr).IP.String()
	association, err := entity.GetPFCPAssociation(nid)
	if err != nil {
		// TODO
		// association may be with a FQDN
	}
	if err == nil {
		return association, nil
	}
	return nil, fmt.Errorf("Entity with NodeID '%s' is has no active association", nid)
}
