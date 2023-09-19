default:
    just --list

test:
    go test -race -v ./...
