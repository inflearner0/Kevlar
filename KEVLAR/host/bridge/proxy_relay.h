#pragma once

// Phase 2 host relay (kevlar_proxy/README.md SS4): the KEVLAR-side counterpart to
// kevlarproxy.sys. Registers DeviceTracker's devices with the driver -- the real
// name(s) the emulated driver itself passed to IoCreateDevice, never hardcoded --
// then runs a pool of worker threads pulling real client IRPs off the inverted-call
// channel (IOCTL_KVP_GET_REQUEST) and answering them via the existing
// IoManager::Dispatch* entry points, same as bridge_server.cpp's Phase 1 pipe --
// just a different transport. Opt-in: only active when the host passes --proxy.
namespace ProxyRelay {

// Opens \\.\KevlarProxyCtl and starts the worker pool. Registers whatever devices
// DeviceTracker already has, then keeps watching for more on a background thread
// for as long as the relay is active -- a driver that creates its device from a
// worker thread or deferred init *after* DriverEntry returns still gets picked up,
// typically within kRegistrarPollMs. Returns false only if the control device
// can't be opened/owned at all (e.g. kevlarproxy.sys isn't loaded, or another
// instance already owns it); having zero devices registered yet is not a failure.
bool Start();

// Cancels outstanding I/O, joins the worker pool, and closes the control handle
// (which also makes kevlarproxy.sys tear down every exposed device it created).
void Stop();

bool IsActive();

} // namespace ProxyRelay
