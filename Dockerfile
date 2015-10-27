FROM gliderlabs/alpine:3.2
MAINTAINER Arthur Barros <arthbarros@gmail.com>

RUN apk --update add python

COPY . /app
WORKDIR /app

ENTRYPOINT ["python"]
CMD ["dnsteal.py", "0.0.0.0"]