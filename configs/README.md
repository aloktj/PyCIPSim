# Example live test configurations

This directory contains ready-to-use JSON configuration files for a two-VM
lab that mirrors the troubleshooting scenario reported in issue discussions.

* `device1_target.json` – load on the VM with IP `172.16.0.150` to start the
  ENIP target runtime bound to `enp0s9`. The configuration pins both the
  listener host and the allowed originator (`172.16.0.250`) so the runtime
  always binds to the Device1 address and only trusts packets from Device2.
  The sample leaves `receive_address` unset because these examples rely on
  unicast I/O; supply the multicast group (e.g. `239.192.1.3`) and set
  `multicast: true` if your lab expects the target-to-originator leg to use
  Class 1 multicast traffic.
* `device2_originator.json` – load on the VM with IP `172.16.0.250` to run the
  originator against Device1 using the ENIP transport. The configuration sets
  the listener host to the Device2 address so any local socket binding (for
  example when restricting to the `enp0s9` interface) is explicit, and it
  matches the same assembly layout and forward-open metadata so the CLI or web
  UI can establish a point-to-point session immediately.

Both files use point-to-point transport and a 200 ms Requested Packet Interval
so you will see the full TCP → ENIP RegisterSession → ForwardOpen handshake
followed by Class-1 cyclic traffic on UDP port 44818, matching the reference
packet capture shared in support requests. Feel free to customise assembly
contents to reflect your application-specific signals or to enable multicast by
providing a `receive_address` when required.
