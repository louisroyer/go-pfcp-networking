// Copyright 2022 Louis Royer and the go-pfcp-networking contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package pfcp_networking

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/louisroyer/go-pfcp-networking/pfcputil"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type PFCPEntityInterface interface {
	NodeID() *ie.IE
	RecoveryTimeStamp() *ie.IE
	CreatePFCPAssociation(association *PFCPAssociation) error
	RemovePFCPAssociation(association *PFCPAssociation) error
	GetPFCPAssociation(nid string) (association *PFCPAssociation, err error)
	GetNextRemoteSessionID() uint64
	GetLocalSessions() PFCPSessionMapSEID
	sendTo(msg []byte, dst net.Addr) error
}

type ReceivedMessage struct {
	message.Message
	SenderAddr net.Addr
	Entity     PFCPEntityInterface
}

func (receivedMessage *ReceivedMessage) ReplyTo(responseMessage message.Message) error {
	if !pfcputil.IsMessageTypeRequest(receivedMessage.MessageType()) {
		return fmt.Errorf("receivedMessage shall be a Request Message")
	}
	if !pfcputil.IsMessageTypeResponse(responseMessage.MessageType()) {
		return fmt.Errorf("responseMessage shall be a Response Message")
	}
	if receivedMessage.Sequence() != responseMessage.Sequence() {
		return fmt.Errorf("responseMessage shall have the same Sequence Number than receivedMessage")
	}
	//XXX: message.Message interface does not implement Marshal()
	b := make([]byte, responseMessage.MarshalLen())
	if err := responseMessage.MarshalTo(b); err != nil {
		return err
	}
	if err := receivedMessage.Entity.sendTo(b, receivedMessage.SenderAddr); err != nil {
		return err
	}
	return nil
}

type handler = func(receivedMessage ReceivedMessage) error

type PFCPEntity struct {
	nodeID              *ie.IE
	recoveryTimeStamp   *ie.IE
	handlers            map[pfcputil.MessageType]handler
	conn                *net.UDPConn
	mu                  sync.Mutex
	nextRemoteSessionID uint64
	muSessionID         sync.Mutex
}

func (e *PFCPEntity) sendTo(msg []byte, dst net.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.conn.WriteTo(msg, dst); err != nil {
		return err
	}
	return nil
}

func (e *PFCPEntity) GetNextRemoteSessionID() uint64 {
	e.muSessionID.Lock()
	id := e.nextRemoteSessionID
	e.nextRemoteSessionID = id + 1
	e.muSessionID.Unlock()
	return id
}

func (e *PFCPEntity) NodeID() *ie.IE {
	return e.nodeID
}
func (e *PFCPEntity) RecoveryTimeStamp() *ie.IE {
	return e.recoveryTimeStamp
}

func newDefaultPFCPEntityHandlers() map[pfcputil.MessageType]handler {
	m := make(map[pfcputil.MessageType]handler)
	m[message.MsgTypeHeartbeatRequest] = handleHeartbeatRequest
	return m
}

func NewPFCPEntity(nodeID string) PFCPEntity {
	return PFCPEntity{
		nodeID:              ie.NewNodeIDHeuristic(nodeID),
		recoveryTimeStamp:   nil,
		handlers:            newDefaultPFCPEntityHandlers(),
		conn:                nil,
		mu:                  sync.Mutex{},
		nextRemoteSessionID: 1,
		muSessionID:         sync.Mutex{},
	}
}

func (e *PFCPEntity) listen() error {
	e.recoveryTimeStamp = ie.NewRecoveryTimeStamp(time.Now())
	// TODO: if NodeID is a FQDN, we can expose multiple ip addresses
	ipAddr, err := e.NodeID().NodeID()
	if err != nil {
		return err
	}
	udpAddr := pfcputil.CreateUDPAddr(ipAddr, pfcputil.PFCP_PORT)
	laddr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return err
	}
	e.conn, err = net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}

	return nil
}

func (e *PFCPEntity) GetHandler(t pfcputil.MessageType) (h handler, err error) {
	if f, exists := e.handlers[t]; exists {
		return f, nil
	}
	return nil, fmt.Errorf("Received unexpected PFCP message type")
}

func (e *PFCPEntity) AddHandler(t pfcputil.MessageType, h handler) error {
	if e.RecoveryTimeStamp() != nil {
		return fmt.Errorf("Cannot add handler to already started PFCP Entity")
	}
	if !pfcputil.IsMessageTypeRequest(t) {
		return fmt.Errorf("Only request messages can have a handler")
	}
	e.handlers[t] = h
	return nil
}

func (e *PFCPEntity) AddHandlers(funcs map[pfcputil.MessageType]handler) error {
	if e.RecoveryTimeStamp() != nil {
		return fmt.Errorf("Cannot add handler to already started PFCP Entity")
	}
	for t, _ := range funcs {
		if !pfcputil.IsMessageTypeRequest(t) {
			return fmt.Errorf("Only request messages can have a handler")
		}
	}

	for t, h := range funcs {
		e.handlers[t] = h
	}
	return nil
}
