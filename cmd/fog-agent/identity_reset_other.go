//go:build !windows

package main

import "errors"

func allowIdentityReset() error { return errors.New("identity reset requires Windows") }
