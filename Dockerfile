FROM python:alpine

RUN mkdir -p /opt
COPY ./pydnsproxy.py /opt/
WORKDIR /opt

CMD ["python","pydnsproxy.py"]
