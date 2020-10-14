with import <nixpkgs> {};
mkShell {
	buildInputs = [ mypy (python3.withPackages (ps: [ps.pyelftools])) ];
}
