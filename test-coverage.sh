#!/bin/bash

# test-coverage.sh
# Script to run Go tests with coverage reporting for EpicServer

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Parse command line arguments
for arg in "$@"
do
    case $arg in
        --no-fail)
        NO_FAIL=true
        shift
        ;;
        --include-test-helpers)
        INCLUDE_TEST_HELPERS=true
        shift
        ;;
        *)
        # Unknown option
        ;;
    esac
done

# Output directory for coverage reports
COVERAGE_DIR="./coverage"
mkdir -p $COVERAGE_DIR

# Set minimum coverage threshold, can be overridden with environment variable
MIN_COVERAGE=${COVERAGE_THRESHOLD:-80}
FAIL_ON_THRESHOLD=${FAIL_ON_THRESHOLD:-true}

# Override fail on threshold if --no-fail was specified
if [ "$NO_FAIL" = true ]; then
    FAIL_ON_THRESHOLD=false
    echo -e "${YELLOW}Running in no-fail mode - will not fail if coverage is below threshold${NC}"
fi

# Option to exclude test helpers, default is true
EXCLUDE_TEST_HELPERS=${EXCLUDE_TEST_HELPERS:-true}

# Override exclude test helpers if --include-test-helpers was specified
if [ "$INCLUDE_TEST_HELPERS" = true ]; then
    EXCLUDE_TEST_HELPERS=false
    echo -e "${YELLOW}Including test helpers in coverage calculation${NC}"
fi

echo -e "${GREEN}Running tests with coverage for EpicServer...${NC}"

# Run tests for the main package and generate coverage profile
if [ "$EXCLUDE_TEST_HELPERS" = true ]; then
    echo -e "${GREEN}Excluding test helpers from coverage calculation...${NC}"
    # Use -coverpkg to specify which packages to include, excluding test helpers
    go test -race -coverprofile=$COVERAGE_DIR/coverage.out -covermode=atomic -coverpkg=$(go list ./... | grep -v helpers_test) ./...
else
    # Include all packages in coverage
    go test -race -coverprofile=$COVERAGE_DIR/coverage.out -covermode=atomic ./...
fi

# Generate HTML coverage report
go tool cover -html=$COVERAGE_DIR/coverage.out -o $COVERAGE_DIR/coverage.html

# Get total coverage percentage
COVERAGE_PCT=$(go tool cover -func=$COVERAGE_DIR/coverage.out | grep total | awk '{print $3}')

echo -e "\n${GREEN}Test Coverage Summary:${NC}"
if [ "$EXCLUDE_TEST_HELPERS" = true ]; then
    echo -e "Total coverage (excluding test helpers): ${YELLOW}$COVERAGE_PCT${NC}"
else
    echo -e "Total coverage: ${YELLOW}$COVERAGE_PCT${NC}"
fi

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
    else
        echo -e "${YELLOW}Ignoring coverage threshold failure due to --no-fail option${NC}"
    fi
fi

echo -e "\n${GREEN}HTML coverage report generated at: ${YELLOW}$COVERAGE_DIR/coverage.html${NC}"
echo -e "Opening coverage report in your default browser..."

# Open the coverage report in the default browser based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    open "$COVERAGE_DIR/coverage.html"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v xdg-open > /dev/null; then
        xdg-open "$COVERAGE_DIR/coverage.html"
    else
        echo -e "${YELLOW}Could not automatically open the browser. Please open $COVERAGE_DIR/coverage.html manually.${NC}"
    fi
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows with Git Bash or similar
    start "$COVERAGE_DIR/coverage.html"
else
    echo -e "${YELLOW}Could not automatically open the browser. Please open $COVERAGE_DIR/coverage.html manually.${NC}"
fi

exit 0 