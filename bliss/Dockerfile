FROM golang:1.24.1

WORKDIR /home/task

COPY ./src/go.mod ./src/go.sum ./
RUN go mod download

COPY ./src/ ./

RUN go build -o finance finance.go
CMD ["./finance"]
