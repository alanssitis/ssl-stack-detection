# Use a base image with the necessary dependencies
FROM ubuntu:20.04

# Install required packages
RUN apt-get update && \
    apt-get install -y build-essential libwolfssl-dev

# Set the working directory
WORKDIR /app

# Copy the client source code into the container
COPY wolfssl_client.c .
COPY server.crt .

# Set the library path
#ENV LD_LIBRARY_PATH=/a/libwolfssl.so.41:$LD_LIBRARY_PATH

# Compile the client application
RUN gcc -o wolfssl_client wolfssl_client.c -lwolfssl -lm

# Specify the command to run when the container starts
CMD ["./wolfssl_client"]

