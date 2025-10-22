"""Simulation orchestration and reporting."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .device import ServiceRequest, ServiceResponse
from .session import CIPSession

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SimulationStep:
    """Represents a single request/expectation pair."""

    request: ServiceRequest
    expected_status: Optional[str] = None
    description: Optional[str] = None


@dataclass
class SimulationResult:
    """Aggregate outcome for a simulation run."""

    steps: List[SimulationStep]
    responses: List[ServiceResponse]
    success: bool
    metrics: "SimulationMetrics"

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "metrics": self.metrics.to_dict(),
            "steps": [
                {
                    "request": step.request.to_dict(),
                    "expected_status": step.expected_status,
                    "description": step.description,
                    "response": (
                        self.responses[index].to_dict()
                        if index < len(self.responses)
                        else None
                    ),
                }
                for index, step in enumerate(self.steps)
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def write_json(self, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8")
        return output_path


@dataclass(slots=True)
class SimulationMetrics:
    """Summary statistics collected during a simulation run."""

    total_steps: int
    completed_steps: int
    success_count: int
    failure_count: int
    average_round_trip_ms: float
    max_round_trip_ms: float
    status_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "average_round_trip_ms": self.average_round_trip_ms,
            "max_round_trip_ms": self.max_round_trip_ms,
            "status_counts": dict(self.status_counts),
        }


@dataclass
class SimulationScenario:
    """Run a collection of simulation steps using a CIP session."""

    session: CIPSession
    steps: Iterable[SimulationStep]
    halt_on_failure: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.steps, list):
            self.steps = list(self.steps)

    def execute(self) -> SimulationResult:
        responses: List[ServiceResponse] = []
        overall_success = True
        success_count = 0
        failure_count = 0
        status_counts: Dict[str, int] = {}

        for index, step in enumerate(self.steps, start=1):
            _LOGGER.info("Executing simulation step %d: %s", index, step.description or "")
            response = self.session.send(step.request)
            responses.append(response)
            status_counts[response.status] = status_counts.get(response.status, 0) + 1
            expectation = step.expected_status
            matches_expectation = expectation is None or response.status == expectation
            if matches_expectation:
                success_count += 1
            else:
                failure_count += 1
                _LOGGER.error(
                    "Step %d expectation mismatch: expected %s, got %s",
                    index,
                    expectation,
                    response.status,
                )
                _LOGGER.error(
                    "Failing request payload: %s",
                    step.request.to_dict(),
                )
                overall_success = False
                if self.halt_on_failure:
                    break
        average_rt = (
            sum(response.round_trip_ms for response in responses) / len(responses)
            if responses
            else 0.0
        )
        max_rt = max((response.round_trip_ms for response in responses), default=0.0)
        metrics = SimulationMetrics(
            total_steps=len(self.steps),
            completed_steps=len(responses),
            success_count=success_count,
            failure_count=failure_count,
            average_round_trip_ms=average_rt,
            max_round_trip_ms=max_rt,
            status_counts=status_counts,
        )
        return SimulationResult(
            steps=list(self.steps),
            responses=responses,
            success=overall_success,
            metrics=metrics,
        )


def load_steps_from_json(path: Path) -> List[SimulationStep]:
    """Load simulation steps from a JSON file."""

    data = json.loads(path.read_text(encoding="utf-8"))
    steps = []
    for entry in data:
        request = ServiceRequest(
            service_code=entry["request"]["service_code"],
            tag_path=entry["request"]["tag_path"],
            payload=(entry["request"].get("payload") or "").encode("latin1") or None,
            metadata=entry["request"].get("metadata", {}),
        )
        steps.append(
            SimulationStep(
                request=request,
                expected_status=entry.get("expected_status"),
                description=entry.get("description"),
            )
        )
    return steps
