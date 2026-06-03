from sqlalchemy import JSON, Boolean, Column, ForeignKey, String, Text

from app.database import Base


class Workspace(Base):
    __tablename__ = "workspaces"

    id = Column(String(36), primary_key=True)
    target_url = Column(String(255), nullable=False)
    verification_nonce = Column(String(64), nullable=False)
    verification_status = Column(Boolean, default=False)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True)
    workspace_id = Column(String(36), ForeignKey("workspaces.id"), nullable=False)
    status = Column(String(50), nullable=False)
    overall_severity = Column(String(20), nullable=True)
    attack_graph_data = Column(JSON, nullable=True)


class Mitigation(Base):
    __tablename__ = "mitigations"

    id = Column(String(36), primary_key=True)
    job_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)
    vulnerability_node = Column(String(100), nullable=False)
    remediation_code = Column(Text, nullable=True)
    # Structured finding metadata: description, risk_level, cves, recommendation.
    # Stored as JSON so new fields can be added without schema migrations.
    finding_metadata = Column(JSON, nullable=True)


class RoutingConfig(Base):
    __tablename__ = "routing_configs"

    role = Column(String(50), primary_key=True)
    email_address = Column(String(255), nullable=False)
