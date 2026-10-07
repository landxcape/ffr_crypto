import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

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

    final outDir = input.outputDirectory;
    await Directory.fromUri(outDir).create(recursive: true);
    final File destFile = File.fromUri(outDir.resolve(libName));

    final bool buildFromSource =
        Platform.environment['FFR_CRYPTO_BUILD_FROM_SOURCE'] == 'true';

    final version = _resolvePackageVersion(input.packageRoot);
    File? prebuiltFile;
    if (!buildFromSource && cargoTarget != null) {
      prebuiltFile = await _resolvePrebuiltBinary(
        packageRoot: input.packageRoot,
        version: version,
        cargoTarget: cargoTarget,
        libName: libName,
      );
    }

    if (prebuiltFile != null && prebuiltFile.existsSync()) {
      await prebuiltFile.copy(destFile.path);
    } else {
      // Compile from source via cargo
      final List<String> cargoArgs = ['build', '--release'];
      if (cargoTarget != null) {
        cargoArgs.addAll(['--target', cargoTarget]);
      }

      Map<String, String>? environment;
      if (targetOS == OS.android && cargoTarget != null) {
        environment = _resolveAndroidEnvironment(
          input: input,
          targetArch: targetArch,
          cargoTarget: cargoTarget,
        );
      } else if (targetOS == OS.macOS || targetOS == OS.iOS) {
        environment = Map<String, String>.from(Platform.environment);
        environment['CARGO_PROFILE_RELEASE_STRIP'] = 'false';
      }

      final result = await Process.run(
        'cargo',
        cargoArgs,
        workingDirectory: rustDir.path,
        environment: environment,
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

      await File.fromUri(libUri).copy(destFile.path);
    }

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

String _resolvePackageVersion(Uri packageRoot) {
  try {
    final pubspecFile = File.fromUri(packageRoot.resolve('pubspec.yaml'));
    if (pubspecFile.existsSync()) {
      for (final line in pubspecFile.readAsLinesSync()) {
        final trimmed = line.trim();
        if (trimmed.startsWith('version:')) {
          return trimmed.substring('version:'.length).trim();
        }
      }
    }
  } catch (_) {}
  return '0.0.9';
}

Future<File?> _resolvePrebuiltBinary({
  required Uri packageRoot,
  required String version,
  required String cargoTarget,
  required String libName,
}) async {
  // 1. Check bundled binary in package
  final bundled = File.fromUri(packageRoot.resolve('blobs/$cargoTarget/$libName'));
  if (bundled.existsSync()) {
    return bundled;
  }

  // 2. Check cached binary in user home cache
  final homeDir = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '';
  if (homeDir.isNotEmpty) {
    final cacheDir = Directory('$homeDir/.cache/ffr_crypto/binaries/$version/$cargoTarget');
    final cachedFile = File('${cacheDir.path}/$libName');
    if (cachedFile.existsSync()) {
      return cachedFile;
    }
  }

  // 3. Attempt download from GitHub Releases
  final url = 'https://github.com/landxcape/ffr_crypto/releases/download/v$version/$cargoTarget-$libName';
  HttpClient? client;
  try {
    client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    final request = await client.getUrl(Uri.parse(url)).timeout(const Duration(seconds: 2));
    final response = await request.close().timeout(const Duration(seconds: 3));
    if (response.statusCode == 200 && homeDir.isNotEmpty) {
      final cacheDir = Directory('$homeDir/.cache/ffr_crypto/binaries/$version/$cargoTarget');
      await cacheDir.create(recursive: true);
      final cachedFile = File('${cacheDir.path}/$libName');
      final sink = cachedFile.openWrite();
      await response.pipe(sink);
      return cachedFile;
    }
  } catch (_) {
    // Network unavailable or release asset not found -> fallback to local cargo build
  } finally {
    client?.close(force: true);
  }

  return null;
}

Map<String, String> _resolveAndroidEnvironment({
  required BuildInput input,
  required Architecture targetArch,
  required String cargoTarget,
}) {
  final env = Map<String, String>.from(Platform.environment);

  int apiLevel = 21;
  try {
    apiLevel = input.config.code.android.targetNdkApi;
  } catch (_) {
    // Default to API 21 if unavailable
  }

  Directory? llvmBinDir;

  final cCompiler = input.config.code.cCompiler;
  if (cCompiler != null) {
    final compilerFile = File.fromUri(cCompiler.compiler);
    if (compilerFile.existsSync()) {
      llvmBinDir = compilerFile.parent;
    }
  }

  if (llvmBinDir == null || !llvmBinDir.existsSync()) {
    final possibleNdkRoots = <String>[
      if (Platform.environment['ANDROID_NDK_HOME'] != null)
        Platform.environment['ANDROID_NDK_HOME']!,
      if (Platform.environment['ANDROID_NDK_ROOT'] != null)
        Platform.environment['ANDROID_NDK_ROOT']!,
      if (Platform.environment['NDK_HOME'] != null)
        Platform.environment['NDK_HOME']!,
      if (Platform.environment['ANDROID_HOME'] != null)
        '${Platform.environment['ANDROID_HOME']}/ndk',
      if (Platform.isMacOS && Platform.environment['HOME'] != null)
        '${Platform.environment['HOME']}/Library/Android/sdk/ndk',
      if (Platform.isLinux && Platform.environment['HOME'] != null)
        '${Platform.environment['HOME']}/Android/Sdk/ndk',
      if (Platform.isWindows && Platform.environment['LOCALAPPDATA'] != null)
        '${Platform.environment['LOCALAPPDATA']}/Android/Sdk/ndk',
    ];

    for (final ndkRootPath in possibleNdkRoots) {
      final ndkRootDir = Directory(ndkRootPath);
      if (!ndkRootDir.existsSync()) continue;

      final ndkDirs = <Directory>[];
      if (File('${ndkRootDir.path}/source.properties').existsSync()) {
        ndkDirs.add(ndkRootDir);
      } else {
        try {
          final entries = ndkRootDir.listSync().whereType<Directory>().toList();
          entries.sort((a, b) => b.path.compareTo(a.path));
          ndkDirs.addAll(entries);
        } catch (_) {}
      }

      for (final ndkDir in ndkDirs) {
        final prebuiltDir = Directory('${ndkDir.path}/toolchains/llvm/prebuilt');
        if (prebuiltDir.existsSync()) {
          for (final hostDir in prebuiltDir.listSync().whereType<Directory>()) {
            final binDir = Directory('${hostDir.path}/bin');
            if (binDir.existsSync()) {
              llvmBinDir = binDir;
              break;
            }
          }
        }
        if (llvmBinDir != null) break;
      }
      if (llvmBinDir != null) break;
    }
  }

  if (llvmBinDir != null && llvmBinDir.existsSync()) {
    final isWindows = Platform.isWindows ? '.cmd' : '';
    String clangName;
    if (targetArch == Architecture.arm) {
      clangName = 'armv7a-linux-androideabi$apiLevel-clang$isWindows';
    } else if (targetArch == Architecture.arm64) {
      clangName = 'aarch64-linux-android$apiLevel-clang$isWindows';
    } else if (targetArch == Architecture.ia32) {
      clangName = 'i686-linux-android$apiLevel-clang$isWindows';
    } else if (targetArch == Architecture.x64) {
      clangName = 'x86_64-linux-android$apiLevel-clang$isWindows';
    } else {
      clangName = 'clang$isWindows';
    }

    final linkerFile = File('${llvmBinDir.path}/$clangName');
    final arName = Platform.isWindows ? 'llvm-ar.exe' : 'llvm-ar';
    final arFile = File('${llvmBinDir.path}/$arName');

    final targetEnvKey = cargoTarget.toUpperCase().replaceAll('-', '_');

    if (linkerFile.existsSync()) {
      env['CARGO_TARGET_${targetEnvKey}_LINKER'] = linkerFile.path;
      env['CC_$cargoTarget'] = linkerFile.path;
    }
    if (arFile.existsSync()) {
      env['CARGO_TARGET_${targetEnvKey}_AR'] = arFile.path;
      env['AR_$cargoTarget'] = arFile.path;
    }

    final currentPath = env['PATH'] ?? '';
    env['PATH'] =
        '${llvmBinDir.path}${Platform.isWindows ? ';' : ':'}$currentPath';
  }

  final currentRustFlags = env['RUSTFLAGS'] ?? '';
  const extraFlags = '-C panic=abort';
  if (!currentRustFlags.contains('panic=abort')) {
    env['RUSTFLAGS'] = currentRustFlags.isEmpty
        ? extraFlags
        : '$currentRustFlags $extraFlags';
  }

  return env;
}
