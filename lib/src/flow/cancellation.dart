part of '../../ffr_crypto_flow.dart';

/// Mutable cooperative cancellation signal for one or more flow executions.
///
/// Cancellation is permanent for this token. Create a new token for unrelated
/// work that must remain independently cancellable.
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
