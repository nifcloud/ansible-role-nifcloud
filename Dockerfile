FROM python:3.6.15
RUN pip install ansible coverage pytest mock requests pytest-cov
WORKDIR /work
