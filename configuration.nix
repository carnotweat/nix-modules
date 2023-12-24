# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).
{
  config,
  pkgs,
  lib,
  ...
}:
let
  ntpF = (idx: "${idx}.amazon.pool.ntp.org");
  lan_mac = "ac:15:a2:ee:66:f4";
  pkgsConfig = {
    allowUnfree = true;
  };
  # profiles
  #   profiles = (
  #   if (builtins.tryEval (import <xtruder/nix-profiles>)).success
  #   then import <xtruder/nix-profiles>
  #   else import (builtins.fetchTarball https://github.com/xtruder/nix-profiles/tarball/v2.0-rc1)
  # );
  # channels

  
  packageSetsOverlay = fixedpoint: pkgs: {
    pkgsUnstable = import (
      fetchTarball https://github.com/NixOS/nixpkgs-channels/archive/nixos-unstable.tar.gz
    ) { config = pkgsConfig; };
    pkgsMaster = import (
      fetchTarball https://github.com/NixOS/nixpkgs/archive/master.tar.gz
    ) { config = pkgsConfig; };
    pkgsLocal = import (
      fetchTarball https://github.com/moaxcp/nixpkgs/archive/local.tar.gz
    ) { config = pkgsConfig; };
  };

  upgradesOverlay = fixedpoint: pkgs: {
    #dropbox = pkgs.pkgsUnstable.dropbox;
    #jbake = pkgs.pkgsUnstable.jbake;
  };

  overlays = [ packageSetsOverlay
               upgradesOverlay
               #final pkgset: previous pkgset aka self,super
               (fixedpoint: pkgs: {
                 git-with-gui = pkgs.git.override { guiSupport = true; };
               })
               (fixedpoint: pkgs: {
                 emacs-with-config = pkgs.callPackage ./modules/emacs/emacs.nix {};
               })
               (fixedpoint: pkgs: {
                 pinentry = pkgs.pinentry.override {
                   enabledFlavors = [ "tty" ];
                 };
               })
               (fixedpoint: pkgs: {
                 openssh = pkgs.openssh.overrideAttrs (old: {
                   patches = (old.patches or [ ]) ++ [ ./openssh.patch ];
                   doCheck = false;
                 });
               })
             ];
  buildEmacs = (pkgs.emacsPackagesFor pkgs.emacs29).emacsWithPackages;
  #epkgs as nixattrs : a composition epkgs is a pkgs-set of emacs, which is a pkg on nix, pkg-set of nixpkg 
   emacsPkg = buildEmacs (epkgs:     
builtins.attrValues {

inherit (epkgs.melpaPackages) magit;

inherit (epkgs.melpaPackages) pass;

inherit (epkgs.melpaPackages) password-store;

inherit (epkgs.melpaPackages) password-store-otp;

inherit (epkgs.melpaPackages) ox-hugo;

inherit (epkgs.melpaPackages) org-roam;

inherit (epkgs.melpaPackages) vterm;

inherit (epkgs.melpaPackages) pdf-tools;

inherit (epkgs.elpaPackages) auctex;

inherit (epkgs.melpaPackages) nix-mode;

inherit (epkgs.melpaPackages) ztree;

inherit (epkgs.melpaPackages) use-package;

inherit (epkgs.elpaPackages) undo-tree;

inherit (epkgs.treesit-grammars) with-all-grammars;

});

in
{
  imports =
    [
      ./hardware-configuration.nix
      ./cachix.nix
      ./home-config.nix
      #profiles.profiles
    ];
  #disabledModules = [ "services/misc/cgit.nix" ];
  ## Monoids ##  
# overlayFoo = self: super: super.lib.fixedPoints.applyOnce "foo" {
#   # like verifying that a property/predicate holds with types
  # };
  nixpkgs.overlays = overlays;
  nixpkgs.config = pkgsConfig;
    nix.extraOptions = ''
    plugin-files = ${pkgs.nix-plugins.override { nix = config.nix.package; }}/lib/nix/plugins/libnix-extra-builtins.so
  '';
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  #more informative rebuild outputs
  system.activationScripts.diff = ''
    if [[ -e /run/current-system ]]; then
      echo -e "\n***            ***          ***           ***           ***\n"
      ${pkgs.nix}/bin/nix store diff-closures /run/current-system "$systemConfig" | grep -w "→" | grep -w "KiB" | column --table --separator " ,:" | ${pkgs.choose}/bin/choose 0:1 -4:-1 | ${pkgs.gawk}/bin/awk '{s=$0; gsub(/\033\[[ -?]*[@-~]/,"",s); print s "\t" $0}' | sort -k5,5gr | ${pkgs.choose}/bin/choose 6:-1 | column --table
      echo -e "\n***            ***          ***           ***           ***\n"
    fi
  '';
  nix.allowedUsers = [ "@wheel" ];

  virtualisation = {
    vswitch.enable = true;
    docker.enable = true;
    docker.rootless = {
      enable = true;
      setSocketVariable = true;
    };
    podman.enable = true;
    #waydroid.enable = true;
  };
  # Bootloader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  # for router and ip failover
  boot.kernel.sysctl."net.ipv4.ip_forward" = "1";
  #  boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = "1";
  #boot.kernelPackages = pkgs.linuxPackages_mptcp;
  #boot.supportedFilesystems = [ "bcachefs" ];

  boot.kernelModules = [ "veth" ];
  boot.kernel.sysctl = {
    "net.ipv4.conf.all.forwarding" = true;
    "net.ipv6.conf.all.forwarding" = true;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.conf.lan0.rp_filter" = 1;
    "net.ipv4.conf.wan0.rp_filter" = 1;
    "net.ipv4.conf.wlan0.rp_filter" = 1;
  };

  #boot.kernelParams = ["ipv6.disable=0"];
  networking.hostName = "nixos"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.


  #wireguard-tools
  # networking.nftables = {
  #   enable = true;
  #   ruleset = ''
  #     table inet filter {
  #       chain input {
  #         type filter hook input priority 0;
  #         iif lo accept
  #         ct state established,related accept
  #         #ip6 protocol icmpv6 accept
  #         ip protocol icmp accept
  #         tcp dport ssh ct state new accept

  #         iif { "eno1" } meta l4proto { udp, tcp } @th,16,16 53 counter accept
  #       }
  #     }
  #   '';
  # };
  # vpn-nftables = {
  #   after = [ "network.target" "network-online.target" "wireguard-tools-wg0.service" ];
  #   requires = [ "network-online.target" "wireguard-tools-wg0.service" ];
  #   wantedBy = [ "default.target" ];
  #   unitConfig = {
  #     StopWhenUnneeded = true;
  #   };
  #   serviceConfig = {
  #     Type = "oneshot";
  #     RemainAfterExit = true;
  #     NetworkNamespacePath = "/var/run/netns/vpn";
  #     ExecStart = "${pkgs.nftables}/bin/nft -f /etc/vpn.conf";
  #     ExecReload = "${pkgs.nftables}/bin/nft -f /etc/vpn.conf";
  #   };
  # }
#  ;
  networking.iproute2 = {
    enable = true;
    rttablesExtraConfig = ''
    #1 wan_table
    2 vpn_table
  '';
  };
  # chain prerouting {
  #   type filter hook prerouting priority 0; policy accept;
  #   # set meta mark to conntrack mark (if already set for this connection)
  #   meta mark set ct mark
  #     # if already marked, just use that mark
  #     mark != 0x0 accept
  #       # set mark to 1
  #       ip saddr $LAN_SPACE meta mark set 0x2
  #       ip6 saddr $LAN6_SPACE meta mark set 0x2
  #       # your rules to choose the route (mark 2 is VPN, mark 1 is no VPN) go here...

  #       # example to route 10.0.0.5 without vpn:
  #       ip saddr 10.0.0.5 meta mark set 0x1

  #       # set conntrack mark (for this connection)
  #       ct mark set mark
  # }
    # Enable networking
    #  networking.networkmanager.enable = true;

    # Enable network manager applet
    programs.nm-applet.enable = true;

  # Set your time zone.
  time.timeZone = "Asia/Kolkata";

  # Select internationalisation properties.
  i18n = {
    defaultLocale = "en_IN";
    #try on another system
    #consoleKeyMap = "dvorak";
    #or dvorak-programmer
  };
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "en_IN";
    LC_IDENTIFICATION = "en_IN";
    LC_MEASUREMENT = "en_IN";
    LC_MONETARY = "en_IN";
    LC_NAME = "en_IN";
    LC_NUMERIC = "en_IN";
    LC_PAPER = "en_IN";
    LC_TELEPHONE = "en_IN";
    LC_TIME = "en_IN";
  };

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the LXQT Desktop Environment.
  # services.xserver.displayManager.lightdm.enable = true;
  # services.xserver.desktopManager.lxqt.enable = true;

  # Enable the Desktop Environment.
 services.xserver.displayManager.lightdm.enable = true;
 services.xserver.desktopManager.lxqt.enable = true;


  # Configure keymap in X11
  services.xserver = {
    layout = "us";
    xkbVariant = "";
    #xkbVariant = "dvp";
  };

  # Enable CUPS to print documents.
  #services.printing.enable = true;
  services.printing = {
    enable = true;
    allowFrom = [ "localhost"  ];
    browsing = true;
    clientConf = ''
    ServerName router.local
  '';
    defaultShared = true;
    #drivers = [ pkgs.hplip ];
    # start on boot, not on socket activation
    startWhenNeeded = false;
  };
  services.lighttpd = {
    enable = true;
  };
#     services.cgit = {
#     enable = true;
#     package = pkgs.callPackage ../services/cgit/default.nix {};
#     domain = "127.0.0.1";
#     subDirectory = "/git";
#     authorizedKeys = [
#       "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbm1/zJQzqBZAV7sVka8mGyCD1qPqAvL0/bO8G9PCNyMw5x0a+V67DWlSON4B5Mp9462NC+ezSmOkuev44q/Byql/OUUKoGNHmXf1ariHQkte7Q9gNu+Lg70g5RCcQ/ik11T3UMey6o7iX64hYL4Dr1cqXuBQ6XflGhlxR+SPxx0CsniPWNyufHCXDu7WP35u9VHt0UxLAHKmbPmvSB91GqEro/FDrnMDDs4p5j70iBn4hSqRc8dk3wdzRITnGKETtRjh8x7QKixC61dpEB0qMNe7Z8kepb1YnQy15CfihLLnG4OMiNkl54iJxBEelgeuQ4krLDPB6hvEpeSNr0jhRJlI/wzXIIQqNa5ABHWC08kIsxx9mwgRbJ2+Bsl0oJeo+drRy71z5xlUkbxL0YCLD0xRCKgf/kHOiJN+e+YdUD4bajwxSyRYZwOeExHdnrd1ES00Xfwnl7/nGdUW9DYMvov6P8uuFwv/jJEGGJgxgnXn69bQn731plGiCjiTpUs8= Android Password Store
# ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8aD3uJ937DKFXN1BYDAezG2umwj4k6 key"
#     ];
#     mirrors = {
#       dotfiles = { owner = "carnotweat"; url = "https://github.com/tdro/dotfiles.git"; };
#       "thedroneely.com" = { owner = "carnotweat"; url = "https://github.com/tdro/thedroneely.com"; };
#     clones = {
#       cgit = { owner = "carnotweat"; url = "https://git.zx2c4.com/cgit"; };
#     };
#     extraConfig = ''
#       robots=noindex
#     '';
#   };
# };
  services.fail2ban = {
    enable = true;
    packageFirewall = pkgs.nftables;
    banaction = "nftables-multiport";
    banaction-allports = "nftables-allport";
  };
  # set force_vpn4 {
  #   type ipv4_addr;
  #   # allow ip ranges
  #   flags interval;
  #   # allow overlapping ip ranges
  #   auto-merge;
  # }
  #   set force_vpn6 {
  #     type ipv6_addr;
  #     flags interval;
  #     auto-merge;
  #   }
    # chain prerouting {

    #     ip daddr @force_vpn4 counter meta mark set 0x2
    #     ip6 daddr @force_vpn6 counter meta mark set 0x2
    #     ct mark set mark
    # }
    # Enable sound with pipewire.
    sound.enable = true;
  hardware.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    #jack.enable = true;

    # use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    #media-session.enable = true;
  };



  # Define a user account. Don't forget to set a password with ‘passwd’.
  #keys.secret-foo.text = builtins.extraBuiltins.pass "secret-foo";
  users.users = {
    dev = {
      isNormalUser = true;
      shell = pkgs.fish;
      config = {
        fetch = https://github.com/carnotweat/nix-modules.git;
        push = "git@github.com:carnotweat/nix-modules.git";      
        install = "./install ${config.networking.hostName}";
      };
      description = "dev";
      extraGroups = [
        "networkmanager"
        "wheel"
        "docker"
      ];
      packages = with pkgs; [
        firefox
        chromium
      ];
    };
    backup = {
      isNormalUser = true;
      openssh.authorizedKeys.keys = [
        ''command="${pkgs.rrsync}/bin/rrsync /home/backup/dir/",restrict ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbm1/zJQzqBZAV7sVka8mGyCD1qPqAvL0/bO8G9PCNyMw5x0a+V67DWlSON4B5Mp9462NC+ezSmOkuev44q/Byql/OUUKoGNHmXf1ariHQkte7Q9gNu+Lg70g5RCcQ/ik11T3UMey6o7iX64hYL4Dr1cqXuBQ6XflGhlxR+SPxx0CsniPWNyufHCXDu7WP35u9VHt0UxLAHKmbPmvSB91GqEro/FDrnMDDs4p5j70iBn4hSqRc8dk3wdzRITnGKETtRjh8x7QKixC61dpEB0qMNe7Z8kepb1YnQy15CfihLLnG4OMiNkl54iJxBEelgeuQ4krLDPB6hvEpeSNr0jhRJlI/wzXIIQqNa5ABHWC08kIsxx9mwgRbJ2+Bsl0oJeo+drRy71z5xlUkbxL0YCLD0xRCKgf/kHOiJN+e+YdUD4bajwxSyRYZwOeExHdnrd1ES00Xfwnl7/nGdUW9DYMvov6P8uuFwv/jJEGGJgxgnXn69bQn731plGiCjiTpUs8= Android Password Store''
  ];
    };
};


  environment.systemPackages = with pkgs; [
    cmake
    #overrides
    #emacs-with-config
    emacs
    git-with-gui
    hut
    pinentry
    gnupg1
    pass
    #passmenu
    qtpass
    rofi-pass
    step-cli
    certmgr
    stunnel
    ripgrep
    (pkgs.pass.withExtensions (exts: [
      exts.pass-otp
      #exts.pass-botp
      exts.pass-tomb
      exts.pass-update
      #exts.ob-pass-menu
      #exts.tmux-pass
      #exts.upass
      #exts.pass-git-helper
      #exts.pass-zsh-completion
      #exts.passff
      #exts.pass-ssh
      #exts.pass-tail
      #exts.pass-pwned
      #exts.pass-clip
      #exts.pass-sclip
      exts.pass-import
      #exts.pass-gen
      #exts.pass-qr
      #exts.pass-backup
      exts.pass-audit
      exts.pass-genphrase
      exts.pass-import
      #exts.pass-export
      exts.pass-update
    ]
    ))
    paperkey
    qrencode
    #zbarcam
    #zbar-tools
    (lib.hiPrio emacsPkg)
    mininet
    sqlite
    # not universal for all pythons but it works for now
    (python3.withPackages (p: [(p.mininet-python.overrideAttrs (_: {
      postInstall = "cp $py/bin/mn $py/lib/python3.10/site-packages/mininet/__main__.py";
    }))]))
    #fp
    pipx
    agda
    #cedille
    haskellPackages.lentil
    hugo
    #bwrap
    sourcehut.python
    ##
    #networking
    adguardhome
    mitmproxy
    libcap
    knot-dns
    config.services.headscale.package
    gitea
    sanoid
    cockpit
    linux-wifi-hotspot
    ocserv
    sshuttle
    autossh
    #howl    
    nurl
    nftables
    iptables
    wireguard-tools
    clamav
    ##
    #nix
    cachix
    npins
    nvd
    nixos-option
    lshw
    busybox
    fish
    nix-output-monitor
    ##
    #suckless
    surf
    sent
    st
    ii
    sic
    tabbed
    dmenu
    tmux
    zsh
    fzf
    #contour 
    #########
    #risc -v , heads
    openocd
    #boot
    flashrom
    efibootmgr
    parted
    ##
    #vm
    firecracker
    # build env 
    gcc
    zig
    niv
    opam
    #m4
    #bison
    #flex
    glibc
    gnumake
    libtool
    #gnat
    #binutils-unwrapped
    #zlib.dev
    #patchelf
    ####################
    ## auth
    oath-toolkit
    keychain
    ##web
    styx
    openring
    #colmena - now lollypop lib has it
    drone-cli
    ##
    #fs
    bindfs
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.

    programs.gnupg.agent = {
    enable = true;
    pinentryFlavor = "tty";
    enableSSHSupport = true;
    };

    programs.gnupg.package = pkgs.gnupg.override {
      pinentry = pkgs.pinentry-tty;
      guiSupport = false;
    };

  programs.bash.enableCompletion = true;
  programs.zsh = {
    enable = true;
    enableCompletion = true;
    shellAliases = {
      pbcopy = "xclip -selection c";
      pbpaste = "xclip -selection clipboard -o";
    };
    #for hm
    # initExtra = pkgs.lib.mkOrder 1501 ''
    #         if [[ :$SHELLOPTS: =~ :(vi|emacs): ]]; then
    #         source "${pkgs.bash-preexec}/share/bash/bash-preexec.sh"
    #         eval "$(${pkgs.atuin}/bin/atuin init bash)"
    #         fi
    #       '';
  };
programs.git.enable = true;
    #
  #for hm
  # programs.fzf = {
  #     enable = true;
  #     enableBashIntegration = true;
  #     enableFishIntegration = true;
  #   };
  
  programs.fish = {
    enable = true;
    vendor = {
      completions.enable = true;
      config.enable = true;
    };
    #for hm
    #package = pkgs.fish;
    # plugins = [{
    #   name="foreign-env";
    #   src = pkgs.fetchFromGitHub {
    #     owner = "oh-my-fish";
    #     repo = "plugin-foreign-env";
    #     rev = "dddd9213272a0ab848d474d0cbde12ad034e65bc";
    #     sha256 = "00xqlyl3lffc5l0viin1nyp819wf81fncqyz87jx8ljjdhilmgbs";
    #   };
    # }];
# use gpg instead of ssh-agent
    shellInit = let fishUserPaths =
      builtins.concatStringsSep " "
        [
          #"$HOME/.nix-profile/bin" #
          "/run/current-system/sw/bin"
	        #"~/.local/bin"
          #"/nix/var/nix/profiles/default/bin"
        ];
                in ''
                   set fish_user_paths '${fishUserPaths}'
                    '';
    shellAliases = {
    	apkg = "~/.local/bin/apkg";
		  agda-pkg = "~/.local/bin/agda-pkg";
    };
  };
  # programs.fish.enable = true;
  # programs.ssh.extraConfig = ''
  #   Host *
  #     HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-ed25519,ssh-rsa
  #     KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
  #     Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  #     MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
  # '';
  services.openssh.hostKeys = [
    { type = "rsa"; bits = 4096; path = "/etc/ssh/ssh_host_rsa_key"; }
    { type = "ed25519"; bits = 256; path = "/etc/ssh/ssh_host_ed25519_key"; }
  ];
  # services.openssh.extraConfig = ''
  #   KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
  #   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  #   MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
  # '';
  # services
  services.emacs = {
  enable = true;
  package = pkgs.emacs29;
  # extraPackages = epkgs: with epkgs; [
  #   emacsPkg
  #   ];
  };
  #for hm
  # systemd.user.services.emacs.Unit = {
  # After = [ "graphical-session-pre.target" ];
  # PartOf = [ "graphical-session.target" ];
  # };
  #for hm
#   services.gpg-agent = {
#   enable = true;
#   #goes to gpg-agent.conf
#   defaultCacheTtl = 1800;
#   enableSshSupport = true;
#   #defaultCacheTtl = 36000;
#   maxCacheTtl = 36000;
#   defaultCacheTtlSsh = 36000;
#   maxCacheTtlSsh = 36000;
#   extraConfig = ''
#     pinentry-program ${pkgs.pinentry}/bin/pinentry-curses
#     allow-emacs-pinentry
#     allow-loopback-pinentry
#   '';
# };
  services.clamav = {
    daemon.enable = true;
    updater.enable = true;
  };
  services.tailscale.enable = true;
  networking.firewall = {
    checkReversePath = "loose";
    trustedInterfaces = [ "tailscale0" ];
    allowedUDPPorts = [ config.services.tailscale.port ];
  };
  services.powerdns.enable = true;
  services.gitea = {
    enable = true;
    #ReadWritePaths= "/etc/gitea/app.ini";
    package = pkgs.forgejo;
    appName = "forgejo";
    extraConfig = ''
  [server]
  START_SSH_SERVER = true
  SSH_LISTEN_PORT = 22
'';

    settings = {
      service.DISABLE_REGISTRATION = true;
      server = {
        HTTP_PORT = 3200;
        HTTP_ADDR = "127.0.0.1";
        DOMAIN = "git.xameer.co";
        ROOT_URL = "https://git.zuendmasse.de";
        LANDING_PAGE = "/explore/repos";
      };
    };
  };

  services.adguardhome = {
    enable = true;
    mutableSettings = true;
    #openFirewall = true;
    #extraArgs = [];
    settings = {
      #null;
      #schema_version = ;
      bind_port = 3000;
      bind_host = "0.0.0.0";
    };
  };
  # self hosted dns

  # options = {
  #   howl = with lib; {
  #     records = mkOption {
  #       type = types.listOf types.str;
  #       description =
  #         "Authoritative DNS records exposed to every device in the tailnet";
  #     };
  #   };
  # };
  # services.nsd = {
  #   enable = true;
  #   interfaces = [ "0.0.0.0" ];
  #   verbosity = 2;
  #   zones.howl.children = {
  #     "howl.".data = ''
  #       $ORIGIN howl.
  #       $TTL 3600

  #       @ IN SOA howl. tinyslices@gmail.com. ( 2021122201 28800 7200 864000 60 )
  #       @ IN NS louie.howl.

  #       ${lib.concatStringsSep "\n" config.howl.records}
  #     '';
  #   };
  # };
  #systemd services
  systemd.services.update-rkn-blacklist =
    let updateRknBlacklist = with pkgs; writeScript "update-rkn-blacklist" ''
    #! ${bash}/bin/bash
    BLACKLIST=$(${coreutils}/bin/mktemp) || exit 1
    RULESET=$(${coreutils}/bin/mktemp) || exit 1

    ${curl}/bin/curl "https://reestr.rublacklist.net/api/v2/ips/csv/" > $BLACKLIST || (${coreutils}/bin/rm $BLACKLIST && exit 1) || exit 1
    ${coreutils}/bin/echo "add element inet global force_vpn4 {" > $RULESET || (${coreutils}/bin/rm $BLACKLIST && exit 1) || exit 1
    ${gnugrep}/bin/grep '\.' $BLACKLIST >> $RULESET
    ${coreutils}/bin/echo "};" >> $RULESET
    ${coreutils}/bin/echo "add element inet global force_vpn6 {" >> $RULESET
    ${gnugrep}/bin/grep '\:' $BLACKLIST >> $RULESET
    ${coreutils}/bin/echo "};" >> $RULESET
    ${coreutils}/bin/rm $BLACKLIST
    ${nftables}/bin/nft -f $RULESET || (${coreutils}/bin/rm $RULESET && exit 1) || exit 1
    ${coreutils}/bin/rm $RULESET
    exit 0
  '';
    in {
      serviceConfig = {
        Type = "oneshot";
        ExecStart = updateRknBlacklist;
      };
    };
  systemd.timers.update-rkn-blacklist = {
    wantedBy = [ "timers.target" ];
    partOf = [ "update-rkn-blacklist.service" ];
    # Use slightly unusual time to reduce network load,
    # since most people probably set their timers at :00
    timerConfig.OnCalendar = [ "*-*-* *:00:20" ];
  };
  systemd.services = {
    ping-ipv6 = {
      after = [ "network.target" "network-online.target" ];
      wantedBy = [ "default.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.iputils}/bin/ping fd01::2";
        Restart = "on-failure";
        RestartSec = "30s";
      };
    };
    # Just in case... what if IPv4 actually has the
    # same problem, but is simply being used often
    # enough for me not to notice?
    ping-ipv4 = {
      after = [ "network.target" "network-online.target" ];
      wantedBy = [ "default.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.iputils}/bin/ping 10.10.10.2";
        Restart = "on-failure";
        RestartSec = "30s";
      };
    };

  };
  systemd.services.gitea.serviceConfig = lib.mkForce {
    Type = "simple";
    User = config.services.gitea.user;
    Group = "gitea";
    WorkingDirectory = config.services.gitea.stateDir;
    ExecStart = "${pkgs.gitea}/bin/gitea web";
    Restart = "always";
  };
  # custom-network-setup-2 = {
  #   description = "custom network setup 2";
  #   wantedBy = [ "network.target" ];
  #   after = [ "custom-network-setup.service" "network-addresses-lan0.service" ];
  #   unitConfig = {
  #     StopWhenUnneeded = true;
  #   };
  #   serviceConfig = {
  #     Type = "oneshot";
  #     RemainAfterExit = true;
  #     ExecStart = with pkgs; writeScript "custom-network-setup-2-start" ''
  #     #! ${bash}/bin/bash
  #     ${iproute2}/bin/ip -4 route add default via 10.10.10.2
  #     ${iproute2}/bin/ip -6 route add default via fd01::2
  #   '';
  #     ExecStop = with pkgs; writeScript "custom-network-setup-2-stop" ''
  #     #! ${bash}/bin/bash
  #     ${iproute2}/bin/ip -4 route del default via 10.10.10.2
  #     ${iproute2}/bin/ip -6 route del default via fd01::2
  # set the default route for the tables
  # ${iproute2}/bin/ip -4 route add default via 10.10.10.2 table vpn_table
  #   ${iproute2}/bin/ip -6 route add default via fd01::2 table vpn_table
  #     ${iproute2}/bin/ip -4 route add default via 10.10.10.3 table wan_table
  #     ${iproute2}/bin/ip -6 route add default via fd01::3 table wan_table

  #       # now set the routes *inside* the tables so that the default gateway can even be reached!
  #       # I dont know what any of that means, I just copied it from the default rules on the default routing table
  #       ${iproute2}/bin/ip -4 route add 10.10.10.0/24 dev br0 proto kernel scope link src 10.10.10.1 table vpn_table
  #       ${iproute2}/bin/ip -6 route add fd01::/64 dev br0 proto kernel metric 256 pref medium table vpn_table
  #       ${iproute2}/bin/ip -4 route add 10.10.10.0/24 dev br0 proto kernel scope link src 10.10.10.1 table wan_table
  #       ${iproute2}/bin/ip -6 route add fd01::/64 dev br0 proto kernel metric 256 pref medium table wan_table

  #       # Finally, make LAN routable within that table. Dont know what the options mean here either.
  #       ${iproute2}/bin/ip -4 route add 10.0.0.0/24 dev lan0 proto kernel scope link src 10.0.0.1 table vpn_table
  #       ${iproute2}/bin/ip -6 route add fd00::/64 dev lan0 proto kernel metric 256 pref medium table vpn_table
  #       ${iproute2}/bin/ip -4 route add 10.0.0.0/24 dev lan0 proto kernel scope link src 10.0.0.1 table wan_table
  #       ${iproute2}/bin/ip -6 route add fd00::/64 dev lan0 proto kernel metric 256 pref medium table wan_table

  #   '';
  #   };
  # };
  systemd.services.custom-network-setup = {
    description = "custom network setup";
    # before nftables, because it might depend on the configuration we changed
    # before wireguard-tools-wg0 because it *will* depend on the config we changed
    # before dhcpcd because it needs to run in the namespace we will create here
    before = [ "nftables.service" "wireguard-tools-wg0.service" "dhcpcd.service" ];
    wantedBy = [ "network.target" ];
    unitConfig = {
      StopWhenUnneeded = true;
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = with pkgs; writeScript "custom-network-setup-start" ''
      #! ${bash}/bin/bash
      # create namespaces
      ${iproute2}/bin/ip netns add vpn
      ${iproute2}/bin/ip netns add wan
      # move wan0 into the wan namespace
      ${iproute2}/bin/ip link set wan0 netns wan

      # make sure all sysctl variables are set correctly in the new namespaces
      ${iproute2}/bin/ip netns exec wan ${procps}/bin/sysctl net.ipv4.conf.wan0.rp_filter=1
      ${iproute2}/bin/ip netns exec wan ${procps}/bin/sysctl net.ipv4.conf.all.forwarding=1
      ${iproute2}/bin/ip netns exec wan ${procps}/bin/sysctl net.ipv6.conf.all.forwarding=1
    '';
      ExecStop = with pkgs; writeScript "custom-network-setup-start" ''
      ! ${bash}/bin/bash

      ${iproute2}/bin/ip rule del fwmark 1 table wan_table
      ${iproute2}/bin/ip rule del fwmark 2 table vpn_table
      ${iproute2}/bin/ip netns exec vpn ${iproute2}/bin/ip link del veth-wan-b
      ${iproute2}/bin/ip link del veth-wan-a
      ${iproute2}/bin/ip netns exec vpn ${iproute2}/bin/ip link del veth-vpn-b
      ${iproute2}/bin/ip link del veth-vpn-a
      ${iproute2}/bin/ip link del br0
      ${iproute2}/bin/ip netns exec wan ${iproute2}/bin/ip link set wan0 netns 1
      ${iproute2}/bin/ip netns del wan
      ${iproute2}/bin/ip netns del vpn
      # create a bridge - which is like a virtual switch
${iproute2}/bin/ip link add br0 type bridge
# enable it
${iproute2}/bin/ip link set br0 up

# set bridge ip
${iproute2}/bin/ip addr add 10.10.10.1/24 dev br0
${iproute2}/bin/ip addr add fd01::1/64 dev br0

# create a veth device pair, which is like two ends of a virtual ethernet cable
${iproute2}/bin/ip link add veth-vpn-a type veth peer name veth-vpn-b
# attach the first "end" to br0 by setting it as the master bridge, and enable it
${iproute2}/bin/ip link set veth-vpn-a master br0 up
# move the other end to the vpn namespace
${iproute2}/bin/ip link set veth-vpn-b netns vpn
# turn the other end on
${iproute2}/bin/ip netns exec vpn ${iproute2}/bin/ip link set veth-vpn-b up
# then set the ip
${iproute2}/bin/ip netns exec vpn ${iproute2}/bin/ip addr add 10.10.10.2/24 dev veth-vpn-b
${iproute2}/bin/ip netns exec vpn ${iproute2}/bin/ip addr add fd01::2/64 dev veth-vpn-b

# now do the same for the other namespace
${iproute2}/bin/ip link add veth-wan-a type veth peer name veth-wan-b
${iproute2}/bin/ip link set veth-wan-a master br0 up
${iproute2}/bin/ip link set dev veth-wan-b netns wan
${iproute2}/bin/ip netns exec wan ${iproute2}/bin/ip link set veth-wan-b up

ip saddr { 10.10.10.0/24 } jump inbound_lan;
ip6 saddr { fd01::/64 } jump inbound_lan;
${iproute2}/bin/ip rule add fwmark 1 table wan_table
${iproute2}/bin/ip rule add fwmark 2 table vpn_table
    '';
    };
  };


  # open a port in your router

  #working but now compatible with nftables based firewall, choose either
#   networking.firewall.extraCommands = with pkgs.lib; ''
#   ${pkgs.nftables}/bin/nft -f - <<EOF
#   table inet ab-forward;
#   flush table inet ab-forward;
#   table inet ab-forward {
#         chain FORWARD {
#               type filter hook forward priority filter; policy drop;
#               ct state related,established accept


#         }
#   }
#   EOF
# '';

  environment.etc."coredns/blocklist.hosts".source = ../blocklist.hosts;
  services.avahi = {
    enable = true;
    hostName = "router";
    interfaces = [ "lan0" "wlan0" ];
    publish = {
      enable = true;
      addresses = true;
      domain = true;
      userServices = true;
    };
  };
  #   services.udev.extraRules = ''
  #     SUBSYSTEM=="net", ACTION=="add", ATTR{address}==${lan_mac},
  # '';
  services.cockpit = {
    enable = true;
    port = 9090;
    settings = {
      WebService = {
        AllowUnencrypted = true;
      };
    };
  };
  # services.create_ap = {
  #   enable = true;
  #   settings = {
  #     INTERNET_IFACE = "eth0";
  #     WIFI_IFACE = "wlan0";
  #     SSID = "xameer";
  #     PASSPHRASE = "ppt@blrX1";
  #   };
  # };
  # UNBOUND
  services.unbound = {
    enable = true;
    #resolveLocalQueries = false;
    settings.server = {
      interface = [ "0.0.0.0" ];

      prefetch = "yes";
      prefetch-key = "yes";
      harden-glue = "yes";
      hide-version = "yes";
      hide-identity = "yes";
      use-caps-for-id = "yes";
      val-clean-additional = "yes";
      harden-dnssec-stripped = "yes";
      cache-min-ttl = "3600";
      cache-max-ttl = "86400";
      unwanted-reply-threshold = "10000";

      verbosity = "2";
      log-queries = "yes";

      tls-cert-bundle = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

      num-threads = "4";
      infra-cache-slabs = "4";
      key-cache-slabs = "4";
      msg-cache-size = "131721898";
      msg-cache-slabs = "4";
      num-queries-per-thread = "4096";
      outgoing-range = "8192";
      rrset-cache-size = "263443797";
      rrset-cache-slabs = "4";
      minimal-responses = "yes";
      serve-expired = "yes";
      so-reuseport = "yes";

      private-address = [
        "10.0.0.0/8"
        "172.16.0.0/12"
        "192.168.0.0/16"
      ];

      access-control = [
        "127.0.0.0/8 allow"
        "10.0.0.0/8 allow"
      ];

      local-zone = [
        ''"localhost." static''
        ''"127.in-addr.arpa." static''

        #''"${domain}" transparent''
      ];

      local-data = [
        ''"localhost. 10800 IN NS localhost."''
        ''"localhost. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"''

        ''"localhost. 10800 IN A 127.0.0.1"''
        ''"127.in-addr.arpa. 10800 IN NS localhost."''
        ''"127.in-addr.arpa. 10800 IN SOA localhost. nobody.invalid. 2 3600 1200 604800 10800"''
        ''"1.0.0.127.in-addr.arpa. 10800 IN PTR localhost."''
      ];
      # ++ (
      #   mapAttrsToList
      #     (
      #       name: attributes:
      #         ''"${name}.${domain}. IN A ${toString (catAttrs "ip" (singleton attributes))}"''
      #     )
      #     ipReservations
      # ) ++ (
      #   mapAttrsToList
      #     (
      #       name: _:
      #         ''"${name}.${domain} CNAME net1.${domain}"''
      #     )
      #     proxyServices
      # );

      # private-domain = [
      #   ''"${domain}."''
      # ];
    };

    settings.forward-zone = {
      name = ".";
      forward-tls-upstream = "yes";
      forward-addr = [
        "1.1.1.1@853"
        "1.0.0.1@853"
      ];
    };
  };
  systemd.services.unbound.environment.MDNS_ACCEPT_NAMES = "^.*\\.local\\.$";
  systemd.services.wg = {
    description = "wg network interface";
    bindsTo = [ "netns@wg.service" ];
    requires = [ "network-online.target" ];
    after = [ "netns@wg.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = with pkgs; writers.writeBash "wg-up" ''
        set -e
        ${iproute}/bin/ip link add wg0 type wireguard-tools
        ${iproute}/bin/ip link set wg0 netns wg
        ${iproute}/bin/ip -n wg address add <ipv4 VPN addr/cidr> dev wg0
        ${iproute}/bin/ip -n wg -6 address add <ipv6 VPN addr/cidr> dev wg0
        ${iproute}/bin/ip netns exec wg \
          ${wireguard-tools}/bin/wg setconf wg0 /root/myVPNprovider.conf
        ${iproute}/bin/ip -n wg link set wg0 up
        ${iproute}/bin/ip -n wg route add default dev wg0
        ${iproute}/bin/ip -n wg -6 route add default dev wg0
      '';
      ExecStop = with pkgs; writers.writeBash "wg-down" ''
        ${iproute}/bin/ip -n wg route del default dev wg0
        ${iproute}/bin/ip -n wg -6 route del default dev wg0
        ${iproute}/bin/ip -n wg link del wg0
      '';
    };
  };
  # systemd.services.myWireguard-ToolsOnlyService = {
  #   description = "Service that will only have access to the wg0 interface"
  #     bindsTo = [ "netns@wg.service" ];
  #   requires = [ "network-online.target" ];
  #   after = [ "wg.service" ];
  #   serviceConfig = {
  #     ...
  #       NetworkNamespacePath = "/var/run/netns/wg";
  #     ...
  #   };
  # };
  # just in case
  networking.hosts."127.0.0.1" = [ "localhost" ];

  #++ hosted-domains;

  services.coredns = {
    enable = true;
    config =
      ''
      . {
        hosts /etc/coredns/blocklist.hosts {
          fallthrough
        }
        # Cloudflare Forwarding
        forward . 1.1.1.1 1.0.0.1
        cache
      }

      internal.domain {
          template IN A  {
            answer "{{ .Name }} 0 IN A 10.80.0.9"
          }
      }
    '';
  };
  #   security.acme.acceptTerms = true;
  # security.acme.defaults.email = "account@${domain}";
  # security.acme.defaults.dnsProvider = "dnsimple";
  # security.acme.defaults.dnsPropagationCheck = true;
  # security.acme.defaults.reloadServices = [ "nginx" ];
  # security.acme.defaults.credentialsFile = config.lollypops.secrets.files."net1/acme-dnsimple-envfile".path;
  # security.acme.certs = mapAttrs'
  #   (service: _:
  #     nameValuePair "${service}.${domain}" { }
  #   )
  networking = {
    nameservers = [ "127.0.0.1" "::1" ];
    #nftables.enable = true;
    #nftables.rulesetFile = "/etc/nixos/nftables.conf";
    #enableIPv6 = false;
    # If using dhcpcd:
    # dhcpcd.extraConfig = "nohook resolv.conf";
    # If using NetworkManager:
    networkmanager = {
      enable = true;
      #dns = "none";
    };
  };
  #   networking.resolvconf.extraConfig = ''
  #   name_servers="10.10.10.1 fd01::1"
  # '';
  networking.firewall.allowedTCPPorts = [ 80 443 22 53 ];
  #networking.firewall.allowedUDPPorts = [ 53 ];
  services.openssh = {
    enable = true;
    passwordAuthentication = false;
    allowSFTP = false; # Don't set this if you need sftp
    ports = [ 222 ];
    challengeResponseAuthentication = false;
    extraConfig = "UseDNS yes";
    #extraConfig = ''
    #  AllowTcpForwarding yes
    #  X11UseLocalHost no
    #  HostbasedAuthentication yes
    #''
  };

  # add acme upon domain spec
  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.05"; # Did you read the comment?

}
