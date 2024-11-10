package main

import (
	"github.com/portward/registry-auth/.dagger/internal/dagger"
)

type RegistryAuth struct {
	// Project source directory
	//
	// +private
	Source *dagger.Directory
}

func New(
	// Project source directory.
	//
	// +defaultPath="/"
	// +ignore=[".devenv", ".direnv", ".github", ".vscode"]
	source *dagger.Directory,
) RegistryAuth {
	return RegistryAuth{
		Source: source,
	}
}

func (m RegistryAuth) Test(
	// Go version
	//
	// +default="1.23"
	goVersion string,
) *dagger.Container {
	return dag.Go(dagger.GoOpts{
		Version: goVersion,
	}).
		WithSource(m.Source).
		Exec([]string{"go", "test", "-race", "./..."})
}

func (m RegistryAuth) Lint() *dagger.Container {
	return dag.GolangciLint(dagger.GolangciLintOpts{
		Version: golangciLintVersion,
	}).Run(m.Source)
}
