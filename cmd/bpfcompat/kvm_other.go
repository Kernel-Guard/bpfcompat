//go:build !linux

package main

func probeKVM(dev string) kvmStatus {
	return kvmStatus{Detail: "KVM is Linux-only; " + dev + " is not available on this OS"}
}
