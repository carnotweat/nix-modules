{ options, config, lib, pkgs, ... }:
let
  cfg = config.services.foo;
  # Define the settings format used for this program
  settingsFormat = pkgs.formats.json {};
in {

  options.services.foo = {
    enable = lib.mkEnableOption "foo service";

    settings = lib.mkOption {
      type = lib.types.submodule {

        # Declare that the settings option supports arbitrary format values, json here
        freeformType = settingsFormat.type;

        # Declare an option for the port such that the type is checked and this option
        # is shown in the manual.
        options.port = lib.mkOption {
          type = lib.types.port;
          default = 8080;
          description = ''
            Which port this service should listen on.
          '';
        };

      };
      default = {};
      # Add upstream documentation to the settings description
      description = ''
        Configuration for Foo, see
        <link xlink:href="https://example.com/docs/foo"/>
        for supported values.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # We can assign some default settings here to make the service work by just
    # enabling it. We use `mkDefault` for values that can be changed without
    # problems
    services.foo.settings = {
      # Fails at runtime without any value set
      log_level = lib.mkDefault "WARN";

      # We assume systemd's `StateDirectory` is used, so this value is required
      # therefore no mkDefault, forcing the user to use mkForce to override it
      data_path = "/var/lib/foo";

      # Since we use this to create a user we need to know the default value at
      # eval time
      user = lib.mkDefault "foo";
    };

    environment.etc."foo.json".source =
      # The formats generator function takes a filename and the Nix value
      # representing the format value and produces a filepath with that value
      # rendered in the format
      settingsFormat.generate "foo-config.json" cfg.settings;

    # We know that the `user` attribute exists because we set a default value
    # for it above, allowing us to use it without worries here
    users.users.${cfg.settings.user} = {};

    # ...
  };
}
