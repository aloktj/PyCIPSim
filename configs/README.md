# Example live test configurations

This directory contains ready-to-use JSON configuration files for a two-VM
lab that mirrors the troubleshooting scenario reported in issue discussions.

* `device1_target.json` – load on the VM with IP `172.16.0.150` to start the
  ENIP target runtime bound to `enp0s9`. It exposes assemblies 100/101 for
  cyclic output/input data and only accepts traffic from the originator at
  `172.16.0.250`.
* `device2_originator.json` – load on the VM with IP `172.16.0.250` to run the
  originator against Device1 using the ENIP transport. The configuration
  matches the same assembly layout and forward-open metadata so the CLI or web
  UI can establish a point-to-point session immediately.

Both files use point-to-point transport and a 200 ms Requested Packet Interval
so you will see the full TCP → ENIP RegisterSession → ForwardOpen handshake
followed by Class-1 cyclic traffic on UDP port 44818, matching the reference
packet capture shared in support requests. Feel free to customise assembly
contents to reflect your application-specific signals or to enable multicast by
providing a `receive_address` when required.
