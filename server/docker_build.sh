#!/bin/bash 

# James Bettke
# Dell SecureWorks 2016

# A bash script to run the Docker build command.

# Set working directory to script directory 
cd "$(dirname "$(readlink -f "$0")")"

# Build a Docker image and tag it "dcept"
docker build -t dcept .
