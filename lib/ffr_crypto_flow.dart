/// Typed, immutable, single-use cryptographic workflows.
///
/// This library provides flow sources, package-defined steps, explicit custom
/// transformations, cooperative cancellation, and contextual failures. It does
/// not re-export the core or primitives entrypoints; import every package layer
/// used by an application explicitly.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';

part 'src/flow/cancellation.dart';
part 'src/flow/crypto_flow.dart';
part 'src/flow/crypto_step.dart';
part 'src/flow/exceptions.dart';
part 'src/flow/steps.dart';
