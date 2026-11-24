import type { Command } from "../domain/command.js";

export const sbomCycloneDx = "sbom.cdx.json";
export const sbomSpdx = "sbom.spdx.json";

/** Syft catalogs the source directory; one run writes both SBOM formats. */
export const syftCommand = (a: { readonly cwd: string; readonly outDir: string }): Command => ({
  cmd: "syft",
  args: [
    "scan",
    "dir:.",
    "--quiet",
    "--output",
    `cyclonedx-json=${a.outDir}/${sbomCycloneDx}`,
    "--output",
    `spdx-json=${a.outDir}/${sbomSpdx}`,
  ],
  cwd: a.cwd,
});
