#!/bin/bash

# James Bettke
# Dell SecureWorks 2016

# A bash script that runs the DCEPT Docker container. 
# It is assumed that you have already built the Docker 
# container by running the docker_build.sh script

# Set working directory to script directory
cd "$(dirname "$(readlink -f "$0")")"

./launcher.sh -d
