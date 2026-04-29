/**
 * Nix Package Manager
 *
 * Submits packages to a custom flake repository (profullstack/threatcrush-nix).
 * Users can install via: nix profile install github:profullstack/threatcrush-nix
 */

import { BasePackageManager } from './base.js';
import type { ReleaseInfo, SubmissionResult } from './types.js';

const FLAKE_OWNER = 'profullstack';
const FLAKE_REPO = 'threatcrush-nix';
const PACKAGE_NAME = 'threatcrush';

export class NixPackageManager extends BasePackageManager {
  readonly name = 'nix';
  readonly displayName = 'Nix';
  readonly platform = 'linux' as const;
  readonly priority = 9;

  isConfigured(): Promise<boolean> {
    return Promise.resolve(this.config.enabled && !!this.getGitHubToken());
  }

  async checkExisting(version: string): Promise<boolean> {
    try {
      // Check if the version is already in our flake repo
      const file = await this.getFileContent(FLAKE_OWNER, FLAKE_REPO, 'flake.nix');
      if (!file) return false;

      // Check if version is in the flake
      return file.content.includes(`version = "${version}"`);
    } catch {
      return false;
    }
  }

  generateManifest(release: ReleaseInfo): Promise<Record<string, string>> {
    // Find assets for different architectures
    const x86AppImage = this.findAsset(
      release,
      (a) => a.name.includes('x86_64') && a.name.endsWith('.AppImage')
    );

    const x86Sha256 = release.checksums.get(x86AppImage?.name ?? '') ?? '';

    // Generate flake.nix
    const flakeNix = `{
  description = "ThreatCrush - Collaborative screen sharing with remote control";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.\${system};
        pname = "${PACKAGE_NAME}";
        version = "${release.version}";

        src = pkgs.fetchurl {
          url = "https://github.com/profullstack/threatcrush/releases/download/v\${version}/ThreatCrush-\${version}-x86_64.AppImage";
          sha256 = "${x86Sha256 !== '' ? x86Sha256 : 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}";
        };

        appimageContents = pkgs.appimageTools.extractType2 { inherit pname version src; };
      in
      {
        packages = {
          default = pkgs.appimageTools.wrapType2 {
            inherit pname version src;
            extraPkgs = pkgs: with pkgs; [
              xdg-utils
              xdg-desktop-portal
              ydotool
            ];

            extraInstallCommands = ''
              install -m 444 -D \${appimageContents}/threatcrush.desktop $out/share/applications/threatcrush.desktop
              install -m 444 -D \${appimageContents}/usr/share/icons/hicolor/512x512/apps/threatcrush.png \\
                $out/share/icons/hicolor/512x512/apps/threatcrush.png 2>/dev/null || true
              substituteInPlace $out/share/applications/threatcrush.desktop \\
                --replace 'Exec=AppRun' 'Exec=threatcrush' 2>/dev/null || true
            '';

            meta = with pkgs.lib; {
              description = "Collaborative screen sharing with remote control";
              longDescription = ''
                ThreatCrush is a collaborative screen sharing application with simultaneous
                remote mouse and keyboard control. Like Screenhero, but open source.
                Perfect for pair programming, remote support, and collaboration.
              '';
              homepage = "https://threatcrush.com";
              changelog = "https://github.com/profullstack/threatcrush/releases/tag/v\${version}";
              license = licenses.mit;
              maintainers = [ ];
              platforms = [ "x86_64-linux" ];
              mainProgram = "threatcrush";
              sourceProvenance = with sourceTypes; [ binaryNativeCode ];
            };
          };

          ${PACKAGE_NAME} = self.packages.\${system}.default;
        };

        apps.default = {
          type = "app";
          program = "\${self.packages.\${system}.default}/bin/threatcrush";
        };
      }
    );
}
`;

    // Generate README
    const readme = `# ThreatCrush Nix Flake

Nix flake for [ThreatCrush](https://threatcrush.com) - Collaborative screen sharing with remote control.

## Installation

### Using flakes (recommended)

\`\`\`bash
# Install directly
nix profile install github:profullstack/threatcrush-nix

# Or run without installing
nix run github:profullstack/threatcrush-nix
\`\`\`

### Using nix-shell

\`\`\`bash
nix-shell -p "(builtins.getFlake \\"github:profullstack/threatcrush-nix\\").packages.x86_64-linux.default"
\`\`\`

### NixOS configuration

Add to your \`flake.nix\`:

\`\`\`nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    threatcrush.url = "github:profullstack/threatcrush-nix";
  };

  outputs = { self, nixpkgs, threatcrush }: {
    nixosConfigurations.yourhostname = nixpkgs.lib.nixosSystem {
      modules = [
        ({ pkgs, ... }: {
          environment.systemPackages = [
            threatcrush.packages.\${pkgs.system}.default
          ];
          # For Wayland remote control, ensure a compositor portal backend service
          # is enabled on your system (KDE/GNOME/wlroots-specific).
        })
      ];
    };
  };
}
\`\`\`

## Version

Current version: ${release.version}

## License

MIT
`;

    return Promise.resolve({
      'flake.nix': flakeNix,
      'README.md': readme,
    });
  }

  async submit(release: ReleaseInfo, dryRun = false): Promise<SubmissionResult> {
    // Check if already exists
    if (await this.checkExisting(release.version)) {
      return {
        packageManager: this.name,
        status: 'skipped',
        message: `Version ${release.version} already exists in Nix flake`,
        alreadyExists: true,
      };
    }

    const files = await this.generateManifest(release);

    if (dryRun) {
      this.logger.info('Dry run - generated Nix flake files:');
      for (const [path, content] of Object.entries(files)) {
        this.logger.info(`\n--- ${path} ---`);
        console.log(content);
      }
      return {
        packageManager: this.name,
        status: 'skipped',
        message: 'Dry run - flake files generated',
      };
    }

    // Ensure flake repo exists
    await this.ensureRepo(
      FLAKE_OWNER,
      FLAKE_REPO,
      'Nix flake for ThreatCrush - collaborative screen sharing'
    );

    // Submit directly to the flake repo
    const githubFiles = Object.entries(files).map(([path, content]) => ({
      path,
      content,
    }));

    return this.submitDirect(
      FLAKE_OWNER,
      FLAKE_REPO,
      githubFiles,
      `Update threatcrush to ${release.version}`
    );
  }
}
