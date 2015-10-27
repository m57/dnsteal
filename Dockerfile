FROM gliderlabs/alpine:3.2
MAINTAINER Arthur Barros <arthbarros@gmail.com>

RUN apk --update add python

COPY . /app
WORKDIR /app

EXPOSE 52

ENTRYPOINT ["python"]
CMD ["dnsteal.py", "0.0.0.0"]