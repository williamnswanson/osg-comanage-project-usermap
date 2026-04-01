FROM library/python:3.11-alpine

LABEL maintainer OSG Software <help@opensciencegrid.org>

COPY *.py /usr/local/bin/

COPY requirements.txt /
RUN pip3 install --upgrade pip && pip3 install --no-cache-dir -r requirements.txt
