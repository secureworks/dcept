#!/bin/bash

# James Bettke
# Dell SecureWorks 2016

# A bash script that runs the DCEPT Docker container. 
# It is assumed that you have already built the Docker 
# container by running the docker_build.sh script. 

# Set working directory to script directory 
cd "$(dirname "$(readlink -f "$0")")"

CONTAINER=$(docker ps -aqf name=dcept)

if [ -n "$CONTAINER" ]; then
	echo "Stopping container named dcept"
	docker stop dcept 1>/dev/null
	echo "Removing container named dcept"
	docker rm dcept 1>/dev/null
fi


if [ -z "$1" ]; then
	arg="-it"
	
else
	arg="-d"
fi

echo "Starting container..."
docker run $arg --name dcept --cap-add=NET_ADMIN -p 80:8080 --net=host -v `pwd`/volume:/opt/dcept/var dcept /opt/dcept/dcept.py 

if [ -n "$1" ]; then
	CONTAINER=$(docker ps -q -f name=dcept) 
	echo "Running DCEPT docker container:" $CONTAINER
	echo 
	docker ps -f name=dcept
	echo -e "\nTo the stop the container run the following command:\n\tdocker stop dcept"
fi
