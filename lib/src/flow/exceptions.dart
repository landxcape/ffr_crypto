part of '../../ffr_crypto_flow.dart';

/// Wraps a source or step failure with stable flow execution context.
final class CryptoFlowException extends CryptoException {
  /// Name of the source or step that failed.
  final String stepName;

  /// Zero-based execution index. Sources use `0`; appended steps start at `1`.
  final int stepIndex;

  /// Original object thrown by the source or step.
  final Object cause;

  /// Original stack trace captured with [cause].
  final StackTrace causeStackTrace;

  /// Creates a contextual wrapper around an original source or step failure.
  CryptoFlowException({
    required this.stepName,
    required this.stepIndex,
    required this.cause,
    required this.causeStackTrace,
  }) : super('Flow step "$stepName" failed at index $stepIndex');
}

/// Thrown when a single-use flow is run more than once.
final class CryptoFlowStateException extends CryptoException {
  /// Creates a flow lifecycle failure.
  CryptoFlowStateException(super.message);
}

/// Thrown when cooperative flow cancellation is observed at a boundary.
final class CryptoFlowCancelledException extends CryptoException {
  /// Creates the stable cooperative-cancellation failure.
  CryptoFlowCancelledException() : super('Crypto flow was cancelled');
}
