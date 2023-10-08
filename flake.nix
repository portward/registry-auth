{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    devenv.url = "github:cachix/devenv";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devenv.flakeModule
      ];

      systems = [ "x86_64-linux" "aarch64-darwin" ];

      perSystem = { config, self', inputs', pkgs, system, ... }: rec {
        devenv.shells = {
          default = {
            languages = {
              go.enable = true;
              go.package = pkgs.lib.mkDefault pkgs.go_1_21;
            };

            packages = with pkgs; [
              just
              # golangci-lint

              # TODO: remove once https://github.com/NixOS/nixpkgs/pull/254878 hits unstable
              (golangci-lint.override (prev: {
                buildGoModule = pkgs.buildGo121Module;
              }))
            ] ++ [ ];

            # https://github.com/cachix/devenv/issues/528#issuecomment-1556108767
            containers = pkgs.lib.mkForce { };
          };

          ci = devenv.shells.default;

          ci_1_21 = {
            imports = [ devenv.shells.ci ];

            languages = {
              go.package = pkgs.go_1_21;
            };
          };
        };
      };
    };
}
