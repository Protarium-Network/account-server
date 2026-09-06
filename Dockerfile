# syntax=docker/dockerfile:1

ARG app_dir="/home/go/app"

FROM golang:1.25-alpine3.22 AS build
ARG app_dir
WORKDIR ${app_dir}

RUN --mount=type=cache,target=/go/pkg/mod/ \
	--mount=type=bind,source=go.sum,target=go.sum \
	--mount=type=bind,source=go.mod,target=go.mod \
	go mod download -x

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod/ \
	CGO_ENABLED=0 go build -v -o ${app_dir}/build/account-server

FROM alpine:3.22 AS final
ARG app_dir
WORKDIR ${app_dir}

RUN addgroup go && adduser -D -G go go
USER go

COPY --from=build ${app_dir}/build/account-server ${app_dir}/account-server

EXPOSE 8080
CMD [ "./account-server" ]
