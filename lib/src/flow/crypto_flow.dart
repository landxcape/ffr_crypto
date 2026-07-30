part of '../../ffr_crypto_flow.dart';

final class _FlowSource {
  final String name;
  final FutureOr<Object?> Function() operation;

  const _FlowSource(this.name, this.operation);
}

final class _ErasedStage {
  final String name;
  final FutureOr<Object?> Function(Object? input) _operation;
  final _NativeStepDescriptor? nativeDescriptor;

  const _ErasedStage._(this.name, this._operation, this.nativeDescriptor);

  static _ErasedStage fromStep<Input, Output>(CryptoStep<Input, Output> step) =>
      _ErasedStage._(
        step.name,
        (input) => step._execute(input as Input),
        step._nativeDescriptor,
      );

  FutureOr<Object?> execute(Object? input) => _operation(input);
}

/// An immutable typed pipeline representing one single-use execution.
///
/// Appending a step creates a fresh independently runnable flow and does not
/// consume this instance. Each individual flow instance may call [run] once.
final class CryptoFlow<Current> {
  final _FlowSource _source;
  final List<_ErasedStage> _stages;
  bool _hasRun = false;

  CryptoFlow._(this._source, List<_ErasedStage> stages)
    : _stages = List.unmodifiable(stages);

  /// Creates a lazy byte source after defensively copying [value].
  static CryptoFlow<Uint8List> fromBytes(Uint8List value) {
    final retained = Uint8List.fromList(value);
    return CryptoFlow._(
      _FlowSource('source.bytes', () => Uint8List.fromList(retained)),
      const [],
    );
  }

  /// Creates a lazy strict hexadecimal source.
  ///
  /// Decoding occurs during [run]. The value must have an even number of digits
  /// and contain no prefix, separator, or whitespace.
  static CryptoFlow<Uint8List> fromHex(String value) => CryptoFlow._(
    _FlowSource('source.hex', () => CryptoBytes.decodeHex(value)),
    const [],
  );

  /// Creates a lazy strict canonical padded standard Base64 source.
  ///
  /// Decoding occurs during [run]. URL-safe, unpadded, whitespace-containing,
  /// and otherwise noncanonical representations are rejected.
  static CryptoFlow<Uint8List> fromBase64(String value) => CryptoFlow._(
    _FlowSource('source.base64', () => CryptoBytes.decodeBase64(value)),
    const [],
  );

  /// Creates a lazy strict UTF-8 source.
  ///
  /// Encoding occurs during [run]. Unpaired UTF-16 surrogate code units are
  /// rejected instead of being replaced.
  static CryptoFlow<Uint8List> fromUtf8(String value) => CryptoFlow._(
    _FlowSource('source.utf8', () => _strictUtf8Encode(value)),
    const [],
  );

  /// Appends a package-defined step whose input matches the current flow type.
  ///
  /// The returned flow is a fresh single-use instance. This flow remains
  /// independently runnable.
  CryptoFlow<Next> then<Next>(CryptoStep<Current, Next> step) =>
      CryptoFlow<Next>._(_source, [
        ..._stages,
        _ErasedStage.fromStep<Current, Next>(step),
      ]);

  /// Appends an explicit caller-controlled synchronous or asynchronous step.
  ///
  /// [name] must not be blank and is included in contextual failures. The
  /// caller owns the transform's security properties, resources, and internal
  /// cancellation behavior.
  CryptoFlow<Next> thenCustom<Next>(
    String name,
    FutureOr<Next> Function(Current input) transform,
  ) {
    if (name.trim().isEmpty) {
      throw InvalidInputException('A custom flow step name must not be empty');
    }
    return then(_OperationStep<Current, Next>(name, transform));
  }

  /// Executes this flow exactly once and returns its final typed value.
  ///
  /// Cancellation is cooperative and is checked before and after the source and
  /// every step. An active operation is allowed to finish; its result is then
  /// discarded when cancellation is observed.
  ///
  /// Source and step failures are wrapped in [CryptoFlowException] with the
  /// original cause and stack trace. Reuse throws [CryptoFlowStateException],
  /// while observed cancellation throws [CryptoFlowCancelledException].
  Future<Current> run({CryptoCancellationToken? cancellationToken}) async {
    if (_hasRun) {
      throw CryptoFlowStateException('A crypto flow can only be run once');
    }
    _hasRun = true;

    final token = cancellationToken ?? CryptoCancellationToken();
    final cleanup = _CleanupStack();
    try {
      token._throwIfCancelled();
      var current = await _invokeFlowStage(_source.name, 0, _source.operation);
      token._throwIfCancelled();
      for (var index = 0; index < _stages.length; index++) {
        final stage = _stages[index];
        token._throwIfCancelled();
        current = await _invokeFlowStage(
          stage.name,
          index + 1,
          () => stage.execute(current),
        );
        token._throwIfCancelled();
      }
      return current as Current;
    } finally {
      await cleanup.releaseAll();
    }
  }
}

Uint8List _strictUtf8Encode(String value) {
  final codeUnits = value.codeUnits;
  for (var index = 0; index < codeUnits.length; index++) {
    final codeUnit = codeUnits[index];
    final isHighSurrogate = codeUnit >= 0xd800 && codeUnit <= 0xdbff;
    final isLowSurrogate = codeUnit >= 0xdc00 && codeUnit <= 0xdfff;

    if (isHighSurrogate) {
      final hasLowSurrogate =
          index + 1 < codeUnits.length &&
          codeUnits[index + 1] >= 0xdc00 &&
          codeUnits[index + 1] <= 0xdfff;
      if (!hasLowSurrogate) {
        throw InvalidInputException('Invalid UTF-16 surrogate sequence');
      }
      index++;
    } else if (isLowSurrogate) {
      throw InvalidInputException('Invalid UTF-16 surrogate sequence');
    }
  }

  return Uint8List.fromList(utf8.encode(value));
}

Future<Object?> _invokeFlowStage(
  String name,
  int index,
  FutureOr<Object?> Function() operation,
) async {
  try {
    return await operation();
  } on CryptoFlowCancelledException {
    rethrow;
  } on CryptoFlowException catch (error, stackTrace) {
    Error.throwWithStackTrace(error, stackTrace);
  } catch (error, stackTrace) {
    throw CryptoFlowException(
      stepName: name,
      stepIndex: index,
      cause: error,
      causeStackTrace: stackTrace,
    );
  }
}

final class _CleanupStack {
  final List<FutureOr<void> Function()> _callbacks = [];
  bool _released = false;

  void register(FutureOr<void> Function() callback) {
    if (_released) {
      throw StateError('Cleanup stack has already been released');
    }
    _callbacks.add(callback);
  }

  Future<void> releaseAll() async {
    if (_released) return;
    _released = true;
    for (final callback in _callbacks.reversed) {
      await callback();
    }
    _callbacks.clear();
  }
}
