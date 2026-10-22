#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/java-tests
javac --release 8 -encoding UTF-8 -d build/java-tests \
  helpdesk-apk/src/com/csl/helpdesk/JiraClient.java tests/java/JiraClientTest.java
java -cp build/java-tests com.csl.helpdesk.JiraClientTest
