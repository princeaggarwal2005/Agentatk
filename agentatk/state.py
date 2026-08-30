import time
import uuid
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


MIN_TRIES_PER_SINK_SOURCE: int = 3


class ResearchBudget(BaseModel):
    max_recon_iterations: int = 15
    max_total_experiments: int = 25
    max_duration_seconds: int = 300
    max_cost_dollars: float = 2.0


class GraphNode(BaseModel):
    id: str
    label: str
    type: Literal["source", "sink", "guardrail", "agent", "entrypoint"]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str = "flows_to"
    status: Literal["candidate", "tested", "confirmed", "blocked"] = "candidate"


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:6].upper()}")
    title: str
    threat_class: str
    source_node: str
    target_sink: str
    rationale: str
    priority: str = "P1"
    sink_tier: Optional[str] = "Tier 1"
    owasp_category: str = "OWASP-LLM01: Prompt Injection"
    mitre_atlas_id: str = "AML.T0051: LLM Prompt Injection"
    score: float = 0.0
    status: Literal["UNTESTED", "PROBING", "CONFIRMED_VULNERABLE", "RESISTED", "GUARDRAIL_BLOCKED", "NEEDS_REVIEW", "HALLUCINATED_TARGET", "INCONCLUSIVE"] = "UNTESTED"
    attempts_count: int = 0
    max_attempts: int = MIN_TRIES_PER_SINK_SOURCE
    created_at: float = Field(default_factory=time.time)
    resolved_at: Optional[float] = None

    @field_validator("priority", mode="before")
    @classmethod
    def normalize_priority(cls, v: Any) -> str:
        s = str(v).upper().strip()
        # Handle literal schema echoes like 'P0 | P1 | P2' or 'P0 (CRITICAL)'
        if "P0" in s or "CRITICAL" in s or "HIGH" in s:
            return "P0"
        if "P2" in s or "LOW" in s:
            return "P2"
        return "P1"


class Experiment(BaseModel):
    experiment_id: str = Field(default_factory=lambda: f"EXP-{uuid.uuid4().hex[:6].upper()}")
    hypothesis_id: str
    attempt_num: int = 1
    stated_intent: str = ""
    injection_channel: Literal["direct_user_turn", "indirect_tool_response", "seeded_file", "environment_var"] = "direct_user_turn"
    rubric_used: str = "indirect_scope_boundary"
    sink_tier: str = "Tier 1"
    owasp_category: str = "OWASP-LLM01: Prompt Injection"
    mitre_atlas_id: str = "AML.T0051: LLM Prompt Injection"
    launch_spec: Dict[str, Any] = Field(default_factory=dict)
    injection_vector: Dict[str, Any] = Field(default_factory=dict)
    canary_token: Optional[str] = None
    
    # Telemetry
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    tool_trace: List[Dict[str, Any]] = Field(default_factory=list)
    network_trace: List[Dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    
    # Verdict & Evaluation
    verdict: Literal["CONFIRMED_VULNERABLE", "RESISTED", "GUARDRAIL_BLOCKED", "NEEDS_REVIEW", "HALLUCINATED_TARGET", "INCONCLUSIVE", "TARGET_ERROR"] = "INCONCLUSIVE"
    verdict_detail: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    judge_justifications: List[str] = Field(default_factory=list)
    judge_samples: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:6].upper()}")
    title: str
    severity: Literal["FATAL", "HIGH", "MEDIUM", "LOW"]
    confidence: float
    target_component: str
    attack_path: str
    threat_class: str
    hypothesis_id: str
    
    # Standards Taxonomy
    owasp_category: str = "OWASP-LLM06: Excessive Agency"
    mitre_atlas_id: str = "AML.T0051: LLM Prompt Injection"
    
    # Provenance
    payload: str
    injection_channel: Literal["direct_user_turn", "indirect_tool_response", "seeded_file", "environment_var"] = "direct_user_turn"
    stated_user_intent: str
    rubric_used: str = "indirect_scope_boundary"
    sink_tier: str = "Tier 1"
    observed_action: Dict[str, Any] = Field(default_factory=dict)
    trace_snippet: List[Dict[str, Any]] = Field(default_factory=list)
    guardrail_bypassed: Optional[str] = None
    impact_summary: str = ""
    judge_reasoning: str = ""
    judge_samples: List[Dict[str, Any]] = Field(default_factory=list)
    reproduction_command: str = ""
    poc_script_path: Optional[str] = None
    patch_diff: Optional[str] = None
    remediation_patch: str = ""
    timestamp: float = Field(default_factory=time.time)


class TargetState(BaseModel):
    target_name: str
    target_root: str
    architecture: Dict[str, Any] = Field(default_factory=dict)
    
    # Surface & Knowledge Graph
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    
    # Detailed Entities
    agents: List[Dict[str, Any]] = Field(default_factory=list)
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    sinks: List[Dict[str, Any]] = Field(default_factory=list)
    guardrails: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Execution Tracking
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    experiments: List[Experiment] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    
    # State Machine & Budget
    current_phase: Literal["RECON", "THREAT_MODEL", "HYPOTHESIS_SELECTION", "EXECUTION", "VERIFICATION", "REPORT"] = "RECON"
    budget: ResearchBudget = Field(default_factory=ResearchBudget)
    recon_iterations_spent: int = 0
    total_experiments_spent: int = 0
    start_time: float = Field(default_factory=time.time)
    end_time: Optional[float] = None

    def add_node(self, node_id: str, label: str, node_type: str, metadata: Optional[Dict[str, Any]] = None):
        if not any(n.id == node_id for n in self.nodes):
            self.nodes.append(GraphNode(id=node_id, label=label, type=node_type, metadata=metadata or {}))

    def add_edge(self, source_id: str, target_id: str, relation: str = "flows_to", status: str = "candidate"):
        if not any(e.source == source_id and e.target == target_id for e in self.edges):
            self.edges.append(GraphEdge(source=source_id, target=target_id, relation=relation, status=status))
