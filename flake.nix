{
  description = "A shell with Go";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        stdenv = pkgs.gccStdenv;
        glibcStatic = pkgs.glibc.static;
      in
      {
        devShells.default = pkgs.mkShell {
          hardeningDisable = [ "fortify" ];
          buildInputs = with pkgs; [
            stdenv
            glibc.static
            delve
            gcc
            go
            gotools
            gopls
            go-outline
            gopkgs
            gocode-gomod
            godef
            golint
          ];
          GOROOT="${pkgs.go}/share/go";
          GOPROXY="https://proxy.golang.org";
          CGO_CFLAGS="-O2 -g -Wno-error";
          CFLAGS="-I${pkgs.glibc.dev}/include";
          LDFLAGS="-L${glibcStatic}/lib";
          CGO_ENABLED=0;
        };
      });
}
