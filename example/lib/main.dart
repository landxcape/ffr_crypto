import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:ffr_crypto/ffr_crypto.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FFR Crypto Demo',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.dark,
        ),
      ),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  // State variables
  String _randomBytesHex = '';
  String _hashResult = '';
  String _rsaKeyPairStatus = 'No key pair generated';
  RsaKeyPair? _rsaKeyPair;
  String _rsaCiphertextHex = '';
  String _rsaDecryptedText = '';

  String _ed25519KeyPairStatus = 'No key pair generated';
  Ed25519KeyPair? _ed25519KeyPair;
  String _ed25519SignatureHex = '';
  bool? _ed25519VerificationResult;

  final TextEditingController _hashController = TextEditingController(
    text: 'Hello FFR Crypto!',
  );
  final TextEditingController _rsaPlaintextController = TextEditingController(
    text: 'Secure RSA Encryption',
  );
  final TextEditingController _ed25519MessageController = TextEditingController(
    text: 'Signed with Ed25519',
  );

  // Helpers
  String _toHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<void> _generateRandom() async {
    try {
      final bytes = await Random.secureBytes(16);
      setState(() {
        _randomBytesHex = _toHex(bytes);
      });
    } catch (e) {
      _showError(e.toString());
    }
  }

  Future<void> _calculateHash(HashAlgorithm algorithm) async {
    try {
      final data = Uint8List.fromList(_hashController.text.codeUnits);
      final digest = await Hash.hash(algorithm, data);
      setState(() {
        _hashResult = '${algorithm.name.toUpperCase()}: ${_toHex(digest)}';
      });
    } catch (e) {
      _showError(e.toString());
    }
  }

  Future<void> _generateRsaKeys() async {
    setState(() => _rsaKeyPairStatus = 'Generating 2048-bit key pair...');
    try {
      final pair = await RsaKeyPair.generate(2048);
      setState(() {
        _rsaKeyPair = pair;
        _rsaKeyPairStatus = 'Key pair generated successfully!';
      });
    } catch (e) {
      setState(() => _rsaKeyPairStatus = 'Generation failed.');
      _showError(e.toString());
    }
  }

  Future<void> _rsaEncryptDecrypt() async {
    if (_rsaKeyPair == null) {
      _showError('Generate RSA key pair first!');
      return;
    }
    try {
      final plaintext = Uint8List.fromList(
        _rsaPlaintextController.text.codeUnits,
      );
      final ciphertext = await Rsa.encrypt(_rsaKeyPair!.publicKey, plaintext);
      final decrypted = await Rsa.decrypt(_rsaKeyPair!.privateKey, ciphertext);

      setState(() {
        _rsaCiphertextHex = _toHex(ciphertext);
        _rsaDecryptedText = String.fromCharCodes(decrypted);
      });
    } catch (e) {
      _showError(e.toString());
    }
  }

  Future<void> _generateEd25519Keys() async {
    setState(() => _ed25519KeyPairStatus = 'Generating Ed25519 keys...');
    try {
      final pair = await Ed25519.generateKeyPair();
      setState(() {
        _ed25519KeyPair = pair;
        _ed25519KeyPairStatus = 'Ed25519 Key pair generated successfully!';
      });
    } catch (e) {
      setState(() => _ed25519KeyPairStatus = 'Generation failed.');
      _showError(e.toString());
    }
  }

  Future<void> _ed25519SignVerify() async {
    if (_ed25519KeyPair == null) {
      _showError('Generate Ed25519 key pair first!');
      return;
    }
    try {
      final message = Uint8List.fromList(
        _ed25519MessageController.text.codeUnits,
      );
      final signature = await Ed25519.sign(
        privateKey: _ed25519KeyPair!.privateKey,
        message: message,
      );
      final verified = await Ed25519.verify(
        publicKey: _ed25519KeyPair!.publicKey,
        message: message,
        signature: signature,
      );

      setState(() {
        _ed25519SignatureHex = _toHex(signature);
        _ed25519VerificationResult = verified;
      });
    } catch (e) {
      _showError(e.toString());
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Error: $message'),
        backgroundColor: Colors.redAccent,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('FFR Crypto Dashboard'),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // CSPRNG Card
            _buildCard(
              title: 'CSPRNG Random Bytes',
              icon: Icons.casino,
              children: [
                ElevatedButton.icon(
                  onPressed: _generateRandom,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Generate 16 Secure Bytes'),
                ),
                if (_randomBytesHex.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  SelectableText(
                    'Hex: $_randomBytesHex',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      color: Colors.greenAccent,
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 16),

            // Hashing Card
            _buildCard(
              title: 'Hash Functions',
              icon: Icons.tag,
              children: [
                TextField(
                  controller: _hashController,
                  decoration: const InputDecoration(
                    labelText: 'Plaintext input',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    ElevatedButton(
                      onPressed: () => _calculateHash(HashAlgorithm.sha256),
                      child: const Text('SHA-256'),
                    ),
                    ElevatedButton(
                      onPressed: () => _calculateHash(HashAlgorithm.sha3_256),
                      child: const Text('SHA3-256'),
                    ),
                    ElevatedButton(
                      onPressed: () => _calculateHash(HashAlgorithm.blake3),
                      child: const Text('BLAKE3'),
                    ),
                  ],
                ),
                if (_hashResult.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  SelectableText(
                    _hashResult,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      color: Colors.blueAccent,
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 16),

            // RSA Card
            _buildCard(
              title: 'RSA Asymmetric Encryption',
              icon: Icons.key,
              children: [
                Text(
                  'Status: $_rsaKeyPairStatus',
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    ElevatedButton(
                      onPressed: _generateRsaKeys,
                      child: const Text('Generate RSA Keys'),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _rsaPlaintextController,
                  decoration: const InputDecoration(
                    labelText: 'Text to encrypt',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),
                ElevatedButton.icon(
                  onPressed: _rsaKeyPair != null ? _rsaEncryptDecrypt : null,
                  icon: const Icon(Icons.lock),
                  label: const Text('Encrypt and Decrypt'),
                ),
                if (_rsaCiphertextHex.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  SelectableText(
                    'Ciphertext: $_rsaCiphertextHex',
                    maxLines: 3,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: Colors.orangeAccent,
                    ),
                  ),
                  const SizedBox(height: 8),
                  SelectableText(
                    'Decrypted Text: $_rsaDecryptedText',
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      color: Colors.green,
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 16),

            // Ed25519 Card
            _buildCard(
              title: 'Ed25519 Signatures',
              icon: Icons.assignment_turned_in,
              children: [
                Text(
                  'Status: $_ed25519KeyPairStatus',
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                ElevatedButton(
                  onPressed: _generateEd25519Keys,
                  child: const Text('Generate Ed25519 Keys'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _ed25519MessageController,
                  decoration: const InputDecoration(
                    labelText: 'Message to sign',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),
                ElevatedButton.icon(
                  onPressed: _ed25519KeyPair != null
                      ? _ed25519SignVerify
                      : null,
                  icon: const Icon(Icons.draw),
                  label: const Text('Sign and Verify'),
                ),
                if (_ed25519SignatureHex.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  SelectableText(
                    'Signature: $_ed25519SignatureHex',
                    maxLines: 2,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: Colors.yellowAccent,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Verification Result: ${_ed25519VerificationResult == true ? "Valid Signature" : "Invalid Signature"}',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: _ed25519VerificationResult == true
                          ? Colors.green
                          : Colors.red,
                    ),
                  ),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCard({
    required String title,
    required IconData icon,
    required List<Widget> children,
  }) {
    return Card(
      elevation: 4,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(icon, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const Divider(height: 24),
            ...children,
          ],
        ),
      ),
    );
  }
}
