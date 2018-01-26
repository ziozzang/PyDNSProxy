FROM python:alpine

RUN mkdir -p /opt
COPY ./ /opt/
WORKDIR /opt

CMD ["python","pydnsproxy.py"]
