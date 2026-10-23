#!/usr/bin/env node
import { main } from "./cli.js";

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`\nagentsec: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  });
