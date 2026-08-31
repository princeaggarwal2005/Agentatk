"""
Google Cloud Firestore & Storage integration for AGENTATK.
Persists audit state, topology graphs, verified findings, PoC scripts,
and remediation diffs directly to Google Cloud infrastructure.
"""

import os
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger("agentatk.gcp")

try:
    from google.cloud import firestore
    FIRESTORE_AVAILABLE = True
except ImportError:
    FIRESTORE_AVAILABLE = False


class GCPStorageManager:
    """
    Manages persistence of AGENTATK security findings and attack surface
    graphs to Google Cloud Firestore and Cloud Storage.
    """

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
        self.client = None
        if FIRESTORE_AVAILABLE:
            try:
                self.client = firestore.Client(project=self.project_id) if self.project_id else firestore.Client()
                logger.info("Google Cloud Firestore client initialized successfully.")
            except Exception as e:
                logger.warning("Google Cloud Firestore client could not be initialized: %s", e)
                self.client = None

    def is_enabled(self) -> bool:
        return self.client is not None

    def save_audit_report(
        self,
        audit_id: str,
        target_name: str,
        results: list,
        stats: dict,
        graph_data: Optional[dict] = None,
    ) -> bool:
        """
        Saves a completed or in-progress audit scorecard to Google Cloud Firestore.
        Collection: 'agentatk_audits'
        """
        if not self.is_enabled():
            return False

        try:
            doc_ref = self.client.collection("agentatk_audits").document(audit_id)
            payload = {
                "audit_id": audit_id,
                "target_name": target_name,
                "timestamp": datetime.utcnow().isoformat(),
                "stats": stats,
                "results_count": len(results),
                "verified_vulnerabilities": sum(1 for r in results if r.get("verdict") == "CONFIRMED_VULNERABLE"),
                "results": results,
                "graph_data": graph_data or {},
                "platform": "Google Cloud Run",
            }
            doc_ref.set(payload, merge=True)
            logger.info("Audit %s successfully synced to Google Cloud Firestore.", audit_id)
            return True
        except Exception as e:
            logger.error("Failed to save audit to Firestore: %s", e)
            return False

    def get_audit_report(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an audit scorecard from Firestore."""
        if not self.is_enabled():
            return None

        try:
            doc_ref = self.client.collection("agentatk_audits").document(audit_id)
            doc = doc_ref.get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error("Failed to read audit from Firestore: %s", e)
            return None


# Global default instance
gcp_store = GCPStorageManager()
