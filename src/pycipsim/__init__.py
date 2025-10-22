"""PyCIPSim - a modular toolkit for simulating Common Industrial Protocol (CIP) scenarios."""

from .session import CIPSession, SessionConfig, TransportError
from .device import (
    DeviceProfile,
    FaultInjection,
    ServiceRequest,
    ServiceResponse,
    make_default_profiles,
)
from .engine import (
    ScenarioExecutionError,
    SimulationScenario,
    SimulationResult,
    SimulationStep,
    SimulationMetrics,
    run_scenarios_parallel,
)
from .config_store import ConfigurationStore, SimulatorConfiguration
from .handshake import HandshakePhase, HandshakeResult, HandshakeStep, perform_handshake

__all__ = [
    "CIPSession",
    "SessionConfig",
    "TransportError",
    "DeviceProfile",
    "FaultInjection",
    "ServiceRequest",
    "ServiceResponse",
    "make_default_profiles",
    "ScenarioExecutionError",
    "SimulationScenario",
    "SimulationResult",
    "SimulationStep",
    "SimulationMetrics",
    "run_scenarios_parallel",
    "ConfigurationStore",
    "SimulatorConfiguration",
    "HandshakePhase",
    "HandshakeResult",
    "HandshakeStep",
    "perform_handshake",
]
