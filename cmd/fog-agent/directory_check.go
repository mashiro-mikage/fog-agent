package main

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

var findDirectoryDC = directoryjoin.FindDomainController
var directoryDCReachable = func(dc string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(dc, "445"), 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// refreshDirectoryCheck only observes. A new context is polled back before action.
func refreshDirectoryCheck(st *enroll.State, check *enroll.DirectoryCheck) (bool, error) {
	if check == nil {
		st.DirectoryCheck = nil
		st.DirectoryObservation = nil
		return false, nil
	}
	if len(check.Revision) != 32 || check.Domain == "" || check.Name == "" {
		return false, errors.New("invalid directory observation context")
	}
	if st.DirectoryObservation != nil && st.DirectoryObservation.Revision == check.Revision && time.Since(st.DirectoryObservedAt) < 5*time.Minute {
		return false, nil
	}
	st.DirectoryObservation = nil
	dc := check.DC
	var err error
	if dc == "" {
		dc, err = findDirectoryDC(check.Domain)
	}
	if err != nil {
		return false, err
	}
	o, err := observeRejoin(dc)
	if err != nil {
		return false, err
	}
	reachable := directoryDCReachable(dc)
	if !reachable {
		o.SecureChannel = "unknown"
	}
	// A DNS name or its actual flat domain is accepted; never derive one by splitting.
	if !strings.EqualFold(o.Domain, check.Domain) && !strings.EqualFold(o.Netbios, check.Domain) {
		o.SecureChannel = "unknown"
	}
	st.DirectoryCheck = check
	st.DirectoryObservation = &enroll.DirectoryObservation{RejoinObservation: o, Revision: check.Revision, DC: dc, DCReachable: reachable}
	st.DirectoryObservedAt = time.Now()
	return true, nil
}
