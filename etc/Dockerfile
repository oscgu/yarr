FROM golang:1.21.5-alpine3.18 AS build
RUN apk add build-base git
WORKDIR /src
COPY . .
RUN make build_linux

FROM alpine:latest
ARG ID
RUN addgroup -g ${ID} yarr && adduser -D -u ${ID} -G yarr yarr
COPY --from=build --chown=yarr:yarr /src/_output/linux/yarr /usr/local/bin/yarr

EXPOSE 7070
ENTRYPOINT [ "/usr/local/bin/yarr" ]
