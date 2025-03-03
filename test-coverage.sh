#!/bin/bash

# test-coverage.sh
# Script to run Go tests with coverage reporting for EpicServer

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Output directory for coverage reports
COVERAGE_DIR="./coverage"
mkdir -p $COVERAGE_DIR

# Set minimum coverage threshold, can be overridden with environment variable
MIN_COVERAGE=${COVERAGE_THRESHOLD:-80}
FAIL_ON_THRESHOLD=${FAIL_ON_THRESHOLD:-true}

echo -e "${GREEN}Running tests with coverage for EpicServer...${NC}"

# Run tests for the main package and generate coverage profile
# Comment out the -race flag to avoid race condition issues
go test -race -coverprofile=$COVERAGE_DIR/coverage.out -covermode=atomic ./...

# Generate HTML coverage report
go tool cover -html=$COVERAGE_DIR/coverage.out -o $COVERAGE_DIR/coverage.html

# Get total coverage percentage
COVERAGE_PCT=$(go tool cover -func=$COVERAGE_DIR/coverage.out | grep total | awk '{print $3}')

echo -e "\n${GREEN}Test Coverage Summary:${NC}"
echo -e "Total coverage: ${YELLOW}$COVERAGE_PCT${NC}"

# Display coverage per package
echo -e "\n${GREEN}Coverage by Package:${NC}"
go tool cover -func=$COVERAGE_DIR/coverage.out

# Generate coverage badge (if needed for README)
COVERAGE_NUM=$(echo $COVERAGE_PCT | tr -d '%')

# Define threshold levels for coverage
if (( $(echo "$COVERAGE_NUM < 70" | bc -l) )); then
    COLOR="red"
    QUALITY="insufficient"
elif (( $(echo "$COVERAGE_NUM < 80" | bc -l) )); then
    COLOR="yellow"
    QUALITY="acceptable"
elif (( $(echo "$COVERAGE_NUM < 90" | bc -l) )); then
    COLOR="green"
    QUALITY="good"
else
    COLOR="brightgreen"
    QUALITY="excellent"
fi

echo -e "\n${GREEN}Coverage Quality: ${YELLOW}$QUALITY${NC}"

# Check coverage against threshold
if (( $(echo "$COVERAGE_NUM < $MIN_COVERAGE" | bc -l) )); then
    echo -e "\n${RED}WARNING: Test coverage is below the minimum threshold of $MIN_COVERAGE%${NC}"
    echo -e "Please add more tests to improve coverage before committing."
    
    # Exit with error only if FAIL_ON_THRESHOLD is true
    if [ "$FAIL_ON_THRESHOLD" = true ]; then
        exit 1
    fi
fi

echo -e "\n${GREEN}HTML coverage report generated at: ${YELLOW}$COVERAGE_DIR/coverage.html${NC}"
echo -e "Open this file in a browser to see detailed coverage information."

exit 0 