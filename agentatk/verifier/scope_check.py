def check_scope(trace, deny=None, allow=None):
    violations = []
    for entry in trace:
        name = entry["tool"]
        if deny and name in deny:
            violations.append(entry)
        elif allow and name not in allow:
            violations.append(entry)
    return {"check": "scope", "passed": len(violations) == 0, "violations": violations}