{
  description = "Shine VPSS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ ];
        pkgs = import nixpkgs { inherit system overlays; };
      in
      with pkgs;
      {
        packages = rec { };
        devShells.default = mkShell {
          buildInputs =
            [
              python312
              sage
            ]
            ++ (with pkgs.python312Packages; [
              # dev
              flake8
              mypy
              black
              ipython
              # deps
              pycryptodome
              numpy
            ]);

          # venvDir = ".virt";

          # postShellHook = ''
          #   pip install --upgrade pip
          #   pip install libecc
          #   pip install cffi
          # '';
        };
      }
    );
}
