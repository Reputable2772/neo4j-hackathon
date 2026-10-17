{
  description = "AgentFence - Modeled AI-agent data-path security prototype";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.python311
            pkgs.python311Packages.pip
            pkgs.python311Packages.virtualenv
            pkgs.git
          ];

          shellHook = ''
            echo "Entering AgentFence devshell..."
            if [ ! -d ".venv" ]; then
              echo "Creating virtual environment in .venv..."
              ${pkgs.python311}/bin/python3 -m venv .venv
              source .venv/bin/activate
              pip install --upgrade pip
              pip install -r requirements.txt
            else
              source .venv/bin/activate
            fi
            export PYTHONPATH="$PWD:$PYTHONPATH"
            echo "AgentFence environment ready. Python: $(python --version)"
          '';
        };
      });
}
