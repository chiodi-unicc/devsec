/**
 * The pinned toolchain `devsec setup` installs. Hashes are SHA-256 of the release archives,
 * copied from each project's published checksums and stored here, so a tampered or
 * re-uploaded archive is rejected instead of trusted.
 */
export const platforms = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"] as const;
export type Platform = (typeof platforms)[number];

export type BinaryTool = {
  readonly name: "trivy" | "syft" | "conftest";
  readonly version: string;
  /** Release asset file name and SHA-256 per platform. */
  readonly assets: Readonly<Record<Platform, { readonly file: string; readonly sha256: string }>>;
  readonly url: (file: string) => string;
};

const gh = (repo: string, tag: string) => (file: string) => `https://github.com/${repo}/releases/download/${tag}/${file}`;

export const binaryTools: readonly BinaryTool[] = [
  {
    name: "trivy",
    version: "0.76.2",
    url: gh("aquasecurity/trivy", "v0.76.2"),
    assets: {
      "darwin-arm64": { file: "trivy_0.76.2_macOS-ARM64.tar.gz", sha256: "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8" },
      "darwin-x64": { file: "trivy_0.76.2_macOS-64bit.tar.gz", sha256: "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b" },
      "linux-arm64": { file: "trivy_0.76.2_Linux-ARM64.tar.gz", sha256: "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3" },
      "linux-x64": { file: "trivy_0.76.2_Linux-64bit.tar.gz", sha256: "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf" },
    },
  },
  {
    name: "syft",
    version: "1.57.2",
    url: gh("anchore/syft", "v1.57.2"),
    assets: {
      "darwin-arm64": { file: "syft_1.57.2_darwin_arm64.tar.gz", sha256: "38afbcc03a9d9afac2d7572432fd2c435e051e03930582ea90f4710ffb515224" },
      "darwin-x64": { file: "syft_1.57.2_darwin_amd64.tar.gz", sha256: "73c6100bc43fbcc1c99aed3428d859c6289c4076be7e296dde7e427324c15908" },
      "linux-arm64": { file: "syft_1.57.2_linux_arm64.tar.gz", sha256: "8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6" },
      "linux-x64": { file: "syft_1.57.2_linux_amd64.tar.gz", sha256: "ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b" },
    },
  },
  {
    name: "conftest",
    version: "0.71.1",
    url: gh("open-policy-agent/conftest", "v0.71.1"),
    assets: {
      "darwin-arm64": { file: "conftest_0.71.1_Darwin_arm64.tar.gz", sha256: "e1cc50d2590b6c5e3da6912666a71264bae82d60bdd62d7ae2b99971ccc8eedd" },
      "darwin-x64": { file: "conftest_0.71.1_Darwin_x86_64.tar.gz", sha256: "a309853b5763c18486768157442d440248ee683b20a2aa1f6b28214e818bd780" },
      "linux-arm64": { file: "conftest_0.71.1_Linux_arm64.tar.gz", sha256: "218c682e110ae7e826dc14a746a6f9b43eb782643dbe730b771fd305634e3f47" },
      "linux-x64": { file: "conftest_0.71.1_Linux_x86_64.tar.gz", sha256: "c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985" },
    },
  },
];

/** Semgrep is a Python package: installed at this version into its own virtual environment. */
export const semgrepTool = { name: "semgrep", version: "1.186.0", minPython: [3, 10] as const } as const;

/** Versions devsec is tested with; `doctor` compares against these. */
export const pinnedVersions: Readonly<Record<string, string>> = {
  ...Object.fromEntries(binaryTools.map((t) => [t.name, t.version])),
  semgrep: semgrepTool.version,
};

/** Pure: "darwin"/"linux" + "arm64"/"x64" → platform key, if supported. */
export const platformOf = (os: string, arch: string): Platform | undefined => {
  const key = `${os}-${arch}`;
  return (platforms as readonly string[]).includes(key) ? (key as Platform) : undefined;
};

/** Layout of the managed toolchain directory (default ~/.devsec/tools). */
export const toolsLayout = (dir: string) => ({
  dir,
  bin: `${dir}/bin`,
  binary: (name: string) => `${dir}/bin/${name}`,
  downloads: `${dir}/downloads`,
  semgrepVenv: `${dir}/semgrep-${semgrepTool.version}`,
});
