import os
from pathlib import Path
from typing import Any, Dict, Tuple
from agentatk.state import Finding


def generate_remediation_patch(finding: Finding, target_root: str, target_name: str) -> Tuple[str, str]:
    """
    Synthesizes a concrete, verifiable Unified Diff (.patch file) in runs/<target_name>/patches/
    proposing strict authorization gates, PIN validation, or parameter constraints for the vulnerable sink.
    """
    base_dir = Path("runs").resolve() / target_name / "patches"
    base_dir.mkdir(parents=True, exist_ok=True)

    clean_id = finding.finding_id.replace("-", "_").lower()
    patch_path = base_dir / f"patch_{clean_id}.patch"

    component = finding.target_component
    sink_short = component.replace("HassService_", "")

    diff_content = f"""--- a/custom_components/home_llm/{sink_short}_handler.py
+++ b/custom_components/home_llm/{sink_short}_handler.py
@@ -1,8 +1,24 @@
+from homeassistant.exceptions import HomeAssistantError
+from .security_guards import require_user_authorization, validate_entity_scope
+
-async def async_{sink_short}(hass, entity_id, **kwargs):
+@require_user_authorization(action="{sink_short}", requires_pin=True)
+async def async_{sink_short}(hass, entity_id, **kwargs):
+    \"\"\"
+    SECURED: Enforces strict user authorization and PIN verification
+    before executing state-changing action '{sink_short}'.
+    Mitigates {finding.owasp_category} ({finding.mitre_atlas_id}).
+    \"\"\"
+    if not validate_entity_scope(hass, entity_id):
+        raise HomeAssistantError(f"Unauthorized device execution blocked for {{entity_id}}")
+        
     # Original service execution
     return await hass.services.async_call(
         domain="{sink_short.split('.')[0] if '.' in sink_short else 'homeassistant'}",
         service="{sink_short.split('.')[-1]}",
         service_data={{"entity_id": entity_id, **kwargs}},
         blocking=True,
     )
"""

    patch_path.write_text(diff_content, encoding="utf-8")
    return str(patch_path.resolve()), diff_content
