#!/bin/bash


PROJECT_DIR=$(dirname "$(realpath $0)")

BUILD_DIR="${PROJECT_DIR}/build"

OUTPUT_DIR="${PROJECT_DIR}/output"

cd "${BUILD_DIR}"
cmake ..
make

if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
fi
