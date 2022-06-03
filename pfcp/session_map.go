// Copyright 2022 Louis Royer and the go-pfcp-networking contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package pfcp_networking

import (
	"sync"

	"github.com/louisroyer/go-pfcp-networking/pfcp/api"
)

type sessionsMapSEID = map[api.SEID]api.PFCPSessionInterface
type sessionsMapFSEID = map[string]sessionsMapSEID
type SessionsMap struct {
	sessions   sessionsMapFSEID
	muSessions sync.Mutex
}

func (sm *SessionsMap) Add(session api.PFCPSessionInterface) error {
	sm.muSessions.Lock()
	defer sm.muSessions.Unlock()
	// Get splitted F-SEID
	localIPAddr, err := session.LocalIPAddress()
	if err != nil {
		return err
	}
	localIP := localIPAddr.String()
	localSEID, err := session.LocalSEID()
	if err != nil {
		return err
	}
	// Create submap if first session with this localIP
	if _, exists := sm.sessions[localIP]; !exists {
		sm.sessions[localIP] = make(sessionsMapSEID, 0)
	}
	// Add session
	sm.sessions[localIP][localSEID] = session
	return nil
}

func NewSessionsMap() SessionsMap {
	return SessionsMap{
		sessions:   make(sessionsMapFSEID, 0),
		muSessions: sync.Mutex{},
	}
}

// Returns pfcpsessions in an array
func (sm *SessionsMap) GetPFCPSessions() []api.PFCPSessionInterface {
	sessions := make([]api.PFCPSessionInterface, 0)
	for _, byseid := range sm.sessions {
		for _, session := range byseid {
			sessions = append(sessions, session)
		}
	}
	return sessions
}
