# Detection module placeholder.
# The detection rule engine and ML anomaly detector live in services/api/:
#   services/api/rules.py    — deterministic rule engine (RULE-001 through RULE-007)
#   services/api/anomaly.py  — IsolationForest ML anomaly detector (RULE-ML-001)
#
# This package is mounted read-only into the API container at /app/detection.
# No additional code is needed here; this file ensures Python treats the directory
# as a package and prevents Docker COPY from omitting it.
