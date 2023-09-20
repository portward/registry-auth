# Registry auth

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/portward/registry-auth/ci.yaml?style=flat-square)](https://github.com/portward/registry-auth/actions/workflows/ci.yaml)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/portward/registry-auth)
[![built with nix](https://img.shields.io/badge/builtwith-nix-7d81f7?style=flat-square)](https://builtwithnix.org)

**Authentication library implementing the [Docker Registry v2 Auth specification](https://github.com/distribution/distribution/blob/42ce5d4d51cad58f5ec835ce0368344aab860300/docs/spec/auth/index.md).**

> [!WARNING]
> **Project is under development. Backwards compatibility is not guaranteed.**

## installation

```shell
go get github.com/portward/registry-auth
```

## Usage

This project is a _library_ that you can use to build your own authorization service for a container registry.

To see it in action, check out [https://github.com/portward/portward](https://github.com/portward/portward).

## Development

**For an optimal developer experience, it is recommended to install [Nix](https://nixos.org/download.html) and [direnv](https://direnv.net/docs/installation.html).**

Run tests:

```shell
go test -race -v ./...
```

Run linter:

```shell
golangci-lint run
```

## License

The project is licensed under the [MIT License](LICENSE).
