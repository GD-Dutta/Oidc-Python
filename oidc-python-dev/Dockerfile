FROM ubuntu:latest

LABEL maintainer="Tarini Prasad Samantaray <tarini@centroxy.com>"

RUN apt-get update
RUN apt-get install -y python3 python3-dev python3-pip nginx
RUN pip3 install uwsgi

COPY ./ ./app
WORKDIR ./app

RUN pip3 install -r requirements.txt

CMD python3 server.py
