# Ferrite package composition

Run the following commands from the repository root with Node.js 22 or later. To change a package, edit its manifest or files in `packages/<name>/src/`, update its README and refresh the index. The package name is its directory name.

```sh
node tools/package-notices.mjs --write
node tools/ferrite-pkg/ferrite-pkg.mjs sync --package <name>
node tools/ferrite-pkg/ferrite-pkg.mjs verify
node --test tools/ferrite-pkg/*.test.mjs packages/mcp/browser/*.test.mjs
```

`sync --package` updates that package's registry entry and any matching mounts declared by consumers in the same workspace. `verify` checks the generated files, lock entries and index against the source tree. For a package with a Cargo harness, run `cargo test --locked --manifest-path packages/<name>/Cargo.toml`. The harness and lockfile belong in the checkout. An application receives the package's source through `ferrite add`.

## Try the change in an application

In a separate app created by `ferrite new`, run `ferrite add <name> --path /absolute/path/to/ferrite-packages`. Follow the module and feature declarations the CLI prints, then run `ferrite check` and `ferrite test`. The CLI verifies each file against the index and installs the named package and its dependencies.

Changes to the root licence or notices affect every installable package. Run `node tools/package-notices.mjs --write` and `node tools/ferrite-pkg/ferrite-pkg.mjs registry` to refresh the entire index after such a change. To check what an application actually receives, run `node tools/check-installed-notices.mjs --cli /path/to/ferrite`. Supply `--registry https://packages.ferrite.cloud/registry.json` to qualify a published release.

## Registry verification

URL installs use a detached Ed25519 signature over the exact registry index bytes. To check a downloaded index and its sibling `registry.json.sig` using the public trust anchor for `packages.ferrite.cloud`, run the following command.

```sh
node tools/ferrite-pkg/registry-sign.mjs verify \
  --trust 'ed25519:Efu7AHD3jlmx6QbnRq3oqOa7HcXV7TUgOyNplBNSG4E=' registry.json
```

The hosted index can include additional packages. The index at `packages/registry.json` describes the sources in this repository.
