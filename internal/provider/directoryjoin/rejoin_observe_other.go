//go:build !windows

package directoryjoin

func ObserveRejoin(dc string) (RejoinObservation, error) {
	return RejoinObservation{}, errObservationUnsupported
}
