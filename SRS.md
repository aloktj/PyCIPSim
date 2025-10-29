# Software Requirements Specification (SRS) for PyCIPSim

## 1. Introduction

### 1.1 Purpose
The purpose of this Software Requirements Specification is to define the functional and non-functional requirements for PyCIPSim, a Python-based simulator that models Ethernet/IP (CIP) communication behaviors for programmable logic controllers (PLCs) and related industrial automation devices.

### 1.2 Scope
PyCIPSim will provide a simulation environment for sending and receiving Common Industrial Protocol (CIP) messages, allowing developers and testers to emulate PLC interactions without requiring physical hardware. The system will focus on using the `pycomm3` Ethernet/IP library to perform communication tasks and will include tooling to facilitate automated testing and analysis of simulated device responses.

### 1.3 Definitions, Acronyms, and Abbreviations
- **CIP**: Common Industrial Protocol, the application-layer protocol used in Ethernet/IP systems.
- **PLC**: Programmable Logic Controller, an industrial digital computer used for automation tasks.
- **Ethernet/IP**: An industrial network protocol that implements CIP over standard Ethernet.
- **`pycomm3`**: A Python library providing client implementations for Ethernet/IP communications.

### 1.4 References
- `pycomm3` project documentation: <https://github.com/ottowayi/pycomm3>
- IEEE Std 830-1998 Software Requirements Specification guidelines.

### 1.5 Overview
The remainder of this document describes the overall system context, detailed functional requirements, interface specifications, non-functional requirements, and supporting tools that will be employed to deliver PyCIPSim.

## 2. Overall Description

### 2.1 Product Perspective
PyCIPSim will operate as a standalone simulation toolkit that can be integrated into existing Python-based testing frameworks and surfaced through a lightweight web dashboard. The simulator will model both client and server behaviors for CIP messaging by leveraging the `pycomm3` library to enforce protocol compliance and message formatting while providing a browser experience for configuration management.

### 2.2 Product Functions
The system will provide functionality to configure simulated devices, persist named configurations, issue CIP service requests, process responses, log transaction data, and inject configurable fault scenarios for robustness testing. Support for automated execution will enable users to script complex test scenarios, while the web application will let operators upload, edit, and activate configurations without touching the command line.

### 2.3 User Classes and Characteristics
Primary users will include automation engineers, software developers, and QA testers who require a lightweight environment to validate CIP integrations. Users are expected to be familiar with Python scripting and basic Ethernet/IP concepts.

### 2.4 Operating Environment
The simulator will run on Python 3.10 or newer in POSIX-compliant environments (Linux, macOS) and Windows. Networking capabilities will rely on the underlying operating system's TCP/IP stack for loopback and remote communications.

### 2.5 Design and Implementation Constraints
The system must rely on `pycomm3` for protocol handling, restricting low-level CIP message construction to interfaces supported by the library. All dependencies must be installable via `pip` without requiring proprietary components. The simulator will adhere to open-source licensing requirements compatible with the project.

### 2.6 User Documentation
The project will deliver README documentation, usage tutorials, and API references describing configuration options, scenario authoring, and integration steps with CI pipelines.

### 2.7 Assumptions and Dependencies
It is assumed that users have access to Python development environments and can install `pycomm3` and supporting packages via PyPI. The simulator depends on `pycomm3` to maintain compliance with Ethernet/IP specifications and to simplify client-server interactions.

## 3. System Features

### 3.1 CIP Session Simulation
1. The system shall allow users to define simulated CIP sessions that connect to virtual or real PLC endpoints using the `pycomm3` library's client interfaces.
2. The system shall support configuration of session parameters, including target IP addresses, ports, connection timeouts, retry counts, multicast receive addresses, and slot identifiers when applicable.
3. The system shall maintain session state, including connection establishment, keep-alive messaging, and graceful teardown procedures.
4. The system shall expose explicit status for TCP socket creation, ENIP register session, and CIP forward-open operations so operators can confirm the entire handshake when acting as the originator.

### 3.2 Message Exchange Engine
1. The system shall send CIP service requests (e.g., Read Tag, Write Tag, Custom Services) using `pycomm3` abstractions and shall capture the responses for analysis.
2. The system shall allow scripted sequences of message exchanges with parameterized payloads to emulate real device workflows.
3. The system shall store each request and response pair with timestamps for auditing and debugging purposes.

### 3.3 Device Simulation Profiles
1. The system shall provide a mechanism to define reusable device profiles that describe expected behaviors, supported services, and error conditions.
2. The system shall allow device profiles to inject simulated faults, such as delayed responses, malformed packets, or CIP status errors, to validate client resilience.
3. The system shall expose configuration hooks for custom Python code to extend device behaviors beyond predefined scenarios.

### 3.4 Monitoring and Logging
1. The system shall offer configurable logging to track CIP communications, including severity levels and log destinations.
2. The system shall integrate with Python's standard logging framework and shall provide structured log messages suitable for parsing by external tools.
3. The system shall supply summary metrics, such as message counts and response times, to support test reporting.

### 3.5 Automation and CI Integration
1. The system shall include a command-line interface that enables batch execution of simulation scenarios with pass/fail exit codes for CI pipelines.
2. The system shall provide Python APIs that allow integration with unit tests written in `pytest` or similar frameworks.
3. The system shall produce machine-readable reports (e.g., JSON) summarizing scenario outcomes for automated analysis.

### 3.6 Web Configuration Management
1. The system shall allow users to upload CIP configuration files via a web interface and persist them for reuse.
2. The system shall present assemblies and signals in tabular form, showing offsets, types, and current values.
3. The system shall prevent modification of signal types, offsets, and names while a simulation is running but permit payload value updates (set/clear) during execution.
4. The system shall provide controls to start and stop the simulator using any saved configuration, updating the displayed handshake status accordingly.
5. The system shall allow users to choose a host network interface for each configuration so live CIP connections originate from the selected adapter.

### 3.7 Live CIP I/O Runtime
1. The system shall establish real TCP, ENIP register session, and CIP forward-open handshakes on demand, keeping connections active for the duration of a simulation.
2. The system shall maintain cyclic producer and consumer loops that publish output assembly images and listen for input assembly payloads at configured intervals for both unicast and multicast transports.
3. The system shall propagate runtime edits to output assembly values onto the active connection, rebuilding payload buffers and transmitting the updated data within the next cyclic interval.
4. The system shall decode inbound assembly payloads into configured signals, update read-only values surfaced in the UI, and persist the captured state for later export.
5. The system shall monitor connection health, recover from timeouts or aborts, and perform orderly forward-close or session teardown when the simulator stops.

**Implementation note:** The current runtime satisfies items 1–4 for unicast sessions by streaming assembly images through the web-managed CIPSession transport. Multicast delivery will be incorporated alongside the UDP adapters described in §4.5.
Operators can continue running the simulator in simulated mode; selecting the live connection mode in the web UI enables the
network-backed behaviour described above.

## 4. External Interface Requirements

### 4.1 User Interfaces
The system shall offer a command-line interface with subcommands for configuring devices, running simulations, launching the web application, and exporting reports. A browser-based interface shall allow users to upload configurations, review assembly tables, and control simulator lifecycle events.

### 4.2 Application Programming Interfaces
The system shall expose Python modules that allow importing classes for session management, device profiles, and scenario orchestration. API functions shall be documented with type hints and docstrings to facilitate IDE support.

### 4.3 Hardware Interfaces
The system shall interact with network interface controllers available on the host machine to send and receive Ethernet/IP packets over TCP/UDP using `pycomm3`. No specialized hardware is required beyond standard network connectivity.

### 4.4 Software Interfaces
The system shall interface with `pycomm3` for Ethernet/IP communications, Python's `asyncio` (if asynchronous operations are required), and optional libraries such as `pytest` for testing and `rich` for enhanced CLI output. Each supporting tool shall be justified based on improved developer ergonomics or testing capabilities.

### 4.5 Communications Interfaces
The system shall support TCP and UDP communications as defined by the Ethernet/IP specification, leveraging `pycomm3` to handle encapsulation and session management. Configuration shall allow users to set custom ports when simulating non-standard environments, as well as multicast or unicast receive addresses for I/O exchange. The handshake helper shall surface status for the TCP, ENIP, and CIP stages to aid troubleshooting.

## 5. Other Nonfunctional Requirements

### 5.1 Performance Requirements
The system shall be capable of handling at least 100 CIP message exchanges per second on commodity hardware while maintaining accurate sequencing and logging. Performance tuning parameters shall be documented for users managing larger workloads.

### 5.2 Safety Requirements
The system shall ensure that simulated traffic remains within user-defined network boundaries to prevent unintended interactions with production devices. Safeguards shall include explicit whitelists of reachable IP addresses and warning prompts before connecting to external networks.
The web dashboard shall expose controls for managing the whitelist (including optional overrides) so operators can authorize
remote lab equipment without editing configuration files manually.

### 5.3 Security Requirements
The system shall avoid storing sensitive credentials in plain text by supporting environment variable configuration and secure credential storage mechanisms when available. Access controls shall restrict modification of simulation configurations to authorized users in shared environments.

### 5.4 Software Quality Attributes
The system shall prioritize maintainability through modular code organization, readability, and comprehensive automated tests. Reliability goals shall target zero unexpected crashes during 24-hour soak tests, and usability goals shall include detailed error messages with actionable guidance.

### 5.5 Business Rules
The system shall maintain compatibility with open-source licensing obligations and shall not include proprietary protocol implementations beyond what is permitted by the `pycomm3` license.

## 6. Supporting Tools and Dependencies

The system shall designate `pycomm3` as the primary dependency for Ethernet/IP interactions due to its active maintenance, protocol coverage, and Pythonic interface. The project shall rely on `uvicorn` to host the FastAPI dashboard, and recommend `pytest` for automated testing because it provides expressive fixtures and integration with CI tools. Optional dependencies such as `rich` may be justified to enhance command-line output readability, while `mypy` or similar static analysis tools may be recommended to improve code quality during development.

## 7. Appendices

### 7.1 Future Enhancements
Future versions may include graphical interfaces for scenario design, support for additional industrial protocols, and cloud-based simulation deployments.

### 7.2 Glossary
A glossary shall be maintained to capture evolving terminology specific to CIP simulation scenarios as new features are implemented.

