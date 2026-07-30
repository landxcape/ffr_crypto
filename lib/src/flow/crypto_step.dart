part of '../../ffr_crypto_flow.dart';

/// An immutable, reusable, package-defined typed flow step.
///
/// Consumers obtain steps from package factories and cannot construct, extend,
/// or implement this type. Use [CryptoFlow.thenCustom] for caller-controlled
/// synchronous or asynchronous transformations.
abstract final class CryptoStep<Input, Output> {
  const CryptoStep._();

  /// Stable non-empty name used for flow error context.
  String get name;

  FutureOr<Output> _execute(Input input);

  _NativeStepDescriptor? get _nativeDescriptor => null;
}

abstract final class _NativeStepDescriptor {
  const _NativeStepDescriptor();
}

final class _OperationStep<Input, Output> extends CryptoStep<Input, Output> {
  @override
  final String name;
  final FutureOr<Output> Function(Input input) _operation;
  @override
  final _NativeStepDescriptor? _nativeDescriptor;

  const _OperationStep(this.name, this._operation, [this._nativeDescriptor])
    : super._();

  @override
  FutureOr<Output> _execute(Input input) => _operation(input);
}
