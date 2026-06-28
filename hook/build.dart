import 'dart:io';
import 'package:logging/logging.dart';
import 'package:hooks/hooks.dart';
import 'package:code_assets/code_assets.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final packageName = input.packageName;

    // Only compile if config.buildCodeAssets is true
    if (!input.config.buildCodeAssets) {
      return;
    }

    final rustDir = Directory.fromUri(input.packageRoot.resolve('rust'));

    // Determine OS and architecture
    final targetOS = input.config.code.targetOS;
    final targetArch = input.config.code.targetArchitecture;

    // Construct Cargo target triple if cross compiling
    String? cargoTarget;
    String libName;
    if (targetOS == OS.macOS) {
      libName = 'libffr_crypto.dylib';
      if (targetArch == Architecture.arm64) {
        cargoTarget = 'aarch64-apple-darwin';
      } else if (targetArch == Architecture.x64) {
        cargoTarget = 'x86_64-apple-darwin';
      }
    } else if (targetOS == OS.linux) {
      libName = 'libffr_crypto.so';
      if (targetArch == Architecture.arm64) {
        cargoTarget = 'aarch64-unknown-linux-gnu';
      } else if (targetArch == Architecture.x64) {
        cargoTarget = 'x86_64-unknown-linux-gnu';
      }
    } else if (targetOS == OS.windows) {
      libName = 'ffr_crypto.dll';
      if (targetArch == Architecture.x64) {
        cargoTarget = 'x86_64-pc-windows-msvc';
      }
    } else if (targetOS == OS.android) {
      libName = 'libffr_crypto.so';
      if (targetArch == Architecture.arm64) {
        cargoTarget = 'aarch64-linux-android';
      } else if (targetArch == Architecture.arm) {
        cargoTarget = 'armv7-linux-androideabi';
      } else if (targetArch == Architecture.ia32) {
        cargoTarget = 'i686-linux-android';
      } else if (targetArch == Architecture.x64) {
        cargoTarget = 'x86_64-linux-android';
      }
    } else if (targetOS == OS.iOS) {
      libName = 'libffr_crypto.dylib';
      if (targetArch == Architecture.arm64) {
        cargoTarget = 'aarch64-apple-ios';
      } else if (targetArch == Architecture.x64) {
        cargoTarget = 'x86_64-apple-ios';
      }
    } else {
      libName = 'libffr_crypto.so';
    }

    final List<String> cargoArgs = ['build', '--release'];
    if (cargoTarget != null) {
      cargoArgs.addAll(['--target', cargoTarget]);
    }

    final result = await Process.run(
      'cargo',
      cargoArgs,
      workingDirectory: rustDir.path,
    );

    if (result.exitCode != 0) {
      throw Exception(
        'Cargo build failed:\n${result.stderr}\n${result.stdout}',
      );
    }

    // Find the built library
    final String targetSubdir = cargoTarget != null
        ? 'target/$cargoTarget/release'
        : 'target/release';
    var libUri = rustDir.uri.resolve('$targetSubdir/$libName');

    // Copy the library to the outputDirectory to bundle it
    final outDir = input.outputDirectory;
    await Directory.fromUri(outDir).create(recursive: true);
    final File srcFile = File.fromUri(libUri);
    if (!await srcFile.exists()) {
      // Try default release if cargo target fallback was used
      final File fallbackFile = File.fromUri(
        rustDir.uri.resolve('target/release/$libName'),
      );
      if (await fallbackFile.exists()) {
        libUri = fallbackFile.uri;
      } else {
        throw Exception('Built library not found at: ${srcFile.path}');
      }
    }

    final File destFile = File.fromUri(outDir.resolve(libName));
    await File.fromUri(libUri).copy(destFile.path);

    output.assets.code.add(
      CodeAsset(
        package: packageName,
        name: 'src/${packageName}_bindings_generated.dart',
        file: destFile.uri,
        linkMode: DynamicLoadingBundled(),
      ),
      routing: const ToAppBundle(),
    );

    // Track rust files as dependencies so build hook re-runs on modification
    final List<Uri> rustDependencies = [];
    final Directory srcDir = Directory.fromUri(rustDir.uri.resolve('src'));
    if (await srcDir.exists()) {
      await for (final entry in srcDir.list(recursive: true)) {
        if (entry is File && entry.path.endsWith('.rs')) {
          rustDependencies.add(entry.uri);
        }
      }
    }
    rustDependencies.add(rustDir.uri.resolve('Cargo.toml'));
    output.dependencies.addAll(rustDependencies);
  });
}
