{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  version = "23.05";
  src = builtins.fetchGit {
    name = "home-manager-${version}";
    url = https://github.com/rycee/home-manager;
    ref = "release-${version}";
  };
in
callPackage "${src}/home-manager" { path = "${src}"; }


