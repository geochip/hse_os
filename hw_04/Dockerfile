FROM ubuntu:24.04

RUN apt-get update && apt-get install -y gcc

COPY main.c /main.c

RUN gcc -o hello main.c

CMD ["/hello"]
