FROM ubuntu:20.04 as builder

RUN apt-get update; \
    apt-get install -y build-essential

WORKDIR /project

COPY . .

RUN make

FROM ubuntu:20.04 as app

COPY --from=builder /project/build/app .

CMD ["./app"]
