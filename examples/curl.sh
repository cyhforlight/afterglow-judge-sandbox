#!/bin/bash
# Example: Execute a simple C++ program via HTTP API

# Compile a simple program
cat > /tmp/hello.cpp << 'EOF'
#include <iostream>
int main() {
    int n;
    std::cin >> n;
    std::cout << n * 2 << std::endl;
    return 0;
}
EOF

g++ -o /tmp/hello /tmp/hello.cpp

# Create input
echo "21" > /tmp/input.txt

# Encode files to base64
EXECUTABLE_BASE64=$(base64 -w 0 /tmp/hello)
INPUT_BASE64=$(base64 -w 0 /tmp/input.txt)

# Send request to server
curl -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d "{
    \"executableBase64\": \"$EXECUTABLE_BASE64\",
    \"inputBase64\": \"$INPUT_BASE64\",
    \"language\": \"C++\",
    \"timeLimit\": 1000,
    \"memoryLimit\": 256
  }" | jq .

# Cleanup
rm -f /tmp/hello /tmp/hello.cpp /tmp/input.txt
