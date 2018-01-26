FROM python:alpine

# default "Redirect ALL"
RUN mkdir -p /opt && echo "* self" > /opt/dns.conf
COPY ./pydnsproxy.py /opt/
WORKDIR /opt

CMD ["python","pydnsproxy.py"]
