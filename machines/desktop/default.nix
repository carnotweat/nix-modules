{ pkgs, ... }:
{
  imports = [
    ./machine.nix
    # ...
  ];

  # pick up location of this machine's configuration
  machine = ./.;

  home.packages = with pkgs; [
    # ...
  ];
}
