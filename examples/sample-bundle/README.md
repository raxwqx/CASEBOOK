# Synthetic CASEBOOK exchange bundle

This bundle contains synthetic, invented observations for demonstrating the CASEBOOK import workflow. It is not collected from a real network or person.

- `manifest.json` describes the bundle format.
- `evidence/` contains sample JSON artifacts.
- `notes/` contains analyst context.

Import the ZIP from the repository root with:

```bash
casebook init DEMO-001 --title "Synthetic Network Lab"
casebook add DEMO-001 examples/casebook-demo-bundle.zip --source "synthetic demo"
casebook verify DEMO-001
casebook report DEMO-001 --format html
```
