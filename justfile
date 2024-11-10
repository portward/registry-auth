default:
    just --list

# Disable Dagger traces setup
export NOTHANKS := "1"

test:
    dagger call test stdout

lint:
    dagger call lint stdout

fmt:
    golangci-lint run --fix
