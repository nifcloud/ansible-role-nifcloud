FROM python:3.6.15
RUN pip install ansible coverage nose mock requests
WORKDIR /work
