part of '../../ffr_crypto_flow.dart';

/// Mutable cooperative cancellation signal for one or more flow executions.
final class CryptoCancellationToken {
  bool _isCancelled = false;

  /// Whether cancellation has been requested.
  bool get isCancelled => _isCancelled;

  /// Requests cancellation at the next flow execution boundary.
  void cancel() {
    _isCancelled = true;
  }

  void _throwIfCancelled() {
    if (_isCancelled) {
      throw CryptoFlowCancelledException();
    }
  }
}
