"""Simulation orchestration and reporting."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

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

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "steps": [
                {
                    "request": step.request.to_dict(),
                    "expected_status": step.expected_status,
                    "description": step.description,
                    "response": response.to_dict(),
                }
                for step, response in zip(self.steps, self.responses)
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def write_json(self, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8")
        return output_path


@dataclass
class SimulationScenario:
    """Run a collection of simulation steps using a CIP session."""

    session: CIPSession
    steps: Iterable[SimulationStep]
    halt_on_failure: bool = True

    def execute(self) -> SimulationResult:
        responses: List[ServiceResponse] = []
        overall_success = True

        for index, step in enumerate(self.steps, start=1):
            _LOGGER.info("Executing simulation step %d: %s", index, step.description or "")
            response = self.session.send(step.request)
            responses.append(response)
            if step.expected_status and response.status != step.expected_status:
                _LOGGER.error(
                    "Step %d expectation mismatch: expected %s, got %s",
                    index,
                    step.expected_status,
                    response.status,
                )
                overall_success = False
                if self.halt_on_failure:
                    break
        return SimulationResult(steps=list(self.steps), responses=responses, success=overall_success)


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
