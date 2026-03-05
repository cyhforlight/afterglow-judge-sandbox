#!/bin/bash
set -euo pipefail

# Example: Submit source code + testcases to judge API

SOURCE_CODE=$(cat <<'PY'
import sys
n = int(sys.stdin.readline())
print(n * 2)
PY
)

curl -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d "{
    \"sourceCode\": $(jq -Rs . <<<"$SOURCE_CODE"),
    \"language\": \"Python\",
    \"timeLimit\": 1000,
    \"memoryLimit\": 256,
    \"testcases\": [
      {\"name\": \"case-1\", \"inputText\": \"21\\n\", \"expectedOutputText\": \"42\\n\"},
      {\"name\": \"case-2\", \"inputText\": \"7\\n\", \"expectedOutputText\": \"14\\n\"}
    ]
  }" | jq .
