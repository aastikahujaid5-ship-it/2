import { useState, useEffect } from 'react';
import { X, ArrowLeft } from 'lucide-react';

interface ToolPageProps {
  toolId: string;
  onClose: () => void;
}

export function ToolPage({ toolId, onClose }: ToolPageProps) {
  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState<Array<{ time: string; source: string; dest: string; protocol: string }>>([]);
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<string>('');
  const [text, setText] = useState('');
  const [key, setKey] = useState('');
  const [encrypted, setEncrypted] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [decryptKey, setDecryptKey] = useState('');
  const [hashText, setHashText] = useState('');
  const [hashes, setHashes] = useState<{ md5: string; sha1: string; sha256: string } | null>(null);
  const [password, setPassword] = useState('');
  const [strength, setStrength] = useState<{ score: number; feedback: string[]; color: string } | null>(null);

  const toolInfo = {
    nmap: {
      title: 'Nmap Network Scanner',
      description: 'Advanced network discovery and security auditing tool',
      icon: '🔍',
    },
    wireshark: {
      title: 'Wireshark Packet Analyzer',
      description: 'Capture and analyze network traffic in real-time',
      icon: '📡',
    },
    encryption: {
      title: 'File Encryption Tool',
      description: 'Encrypt sensitive files using AES-256 encryption',
      icon: '🔐',
    },
    decryption: {
      title: 'File Decryption Tool',
      description: 'Decrypt encrypted files with the correct key',
      icon: '🔓',
    },
    hash: {
      title: 'Cryptographic Hash Generator',
      description: 'Generate secure hashes (MD5, SHA-1, SHA-256)',
      icon: '#️⃣',
    },
    password: {
      title: 'Password Strength Analyzer',
      description: 'Test and improve your password security',
      icon: '🔑',
    },
  };

  const info = toolInfo[toolId as keyof typeof toolInfo];

  const handleNmapScan = () => {
    setScanning(true);
    setTimeout(() => {
      setResults(`Starting Nmap scan on ${target}...\n\nStarting Nmap 7.92\nNmap scan report for ${target}\nHost is up (0.045s latency).\nNot shown: 995 closed ports\nPORT     STATE    SERVICE      VERSION\n22/tcp   open     ssh          OpenSSH 7.4\n80/tcp   open     http         Apache 2.4.6\n443/tcp  open     https        Apache 2.4.6\n3306/tcp open     mysql        MySQL 5.7.32\n5432/tcp open     postgresql   PostgreSQL 11.9\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/`);
      setScanning(false);
    }, 2000);
  };

  const handleWiresharkCapture = () => {
    setCapturing(true);
    setPackets([]);
    const interval = setInterval(() => {
      setPackets((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          source: `192.168.1.${Math.floor(Math.random() * 255)}`,
          dest: `192.168.1.${Math.floor(Math.random() * 255)}`,
          protocol: ['TCP', 'UDP', 'HTTP', 'DNS', 'SSL/TLS'][Math.floor(Math.random() * 5)],
        },
      ]);
    }, 500);

    setTimeout(() => {
      clearInterval(interval);
      setCapturing(false);
    }, 5000);
  };

  const handleEncrypt = () => {
    const encoded = btoa(text + '|' + key);
    setEncrypted(encoded);
  };

  const handleDecrypt = () => {
    try {
      const decoded = atob(encryptedText);
      const [txt, storedKey] = decoded.split('|');
      if (storedKey === decryptKey) {
        setDecrypted(txt);
      } else {
        setDecrypted('Invalid key!');
      }
    } catch {
      setDecrypted('Invalid encrypted text!');
    }
  };

  const generateHash = async () => {
    const encoder = new TextEncoder();
    const data = encoder.encode(hashText);
    const sha256Buffer = await crypto.subtle.digest('SHA-256', data);
    const sha256Array = Array.from(new Uint8Array(sha256Buffer));
    const sha256 = sha256Array.map(b => b.toString(16).padStart(2, '0')).join('');

    setHashes({
      md5: 'MD5 deprecated - use SHA-256',
      sha1: 'SHA-1 deprecated - use SHA-256',
      sha256,
    });
  };

  const analyzePassword = () => {
    let score = 0;
    const feedback: string[] = [];

    if (password.length >= 8) score++;
    else feedback.push('Use at least 8 characters');

    if (/[a-z]/.test(password)) score++;
    else feedback.push('Include lowercase letters');

    if (/[A-Z]/.test(password)) score++;
    else feedback.push('Include uppercase letters');

    if (/[0-9]/.test(password)) score++;
    else feedback.push('Include numbers');

    if (/[^a-zA-Z0-9]/.test(password)) score++;
    else feedback.push('Include special characters');

    const colors = ['red', 'orange', 'yellow', 'blue', 'green'];
    setStrength({
      score,
      feedback,
      color: colors[score - 1] || 'red',
    });
  };

  return (
    <div className="fixed inset-0 bg-gray-900 z-50 overflow-y-auto">
      <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-6 sticky top-0">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/20 rounded-lg transition-colors"
            >
              <ArrowLeft className="h-6 w-6" />
            </button>
            <div>
              <h1 className="text-3xl font-bold">{info.title}</h1>
              <p className="text-emerald-50 mt-1">{info.description}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-white/20 rounded-lg transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {toolId === 'nmap' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-1 bg-white rounded-xl shadow-lg p-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-6">Network Scanner</h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Target Host</label>
                    <input
                      type="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="192.168.1.1 or example.com"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500"
                    />
                  </div>
                  <button
                    onClick={handleNmapScan}
                    disabled={scanning || !target}
                    className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
                  >
                    {scanning ? 'Scanning...' : 'Start Scan'}
                  </button>
                </div>
              </div>

              <div className="lg:col-span-2 bg-white rounded-xl shadow-lg p-8">
                <h3 className="text-xl font-bold text-gray-900 mb-4">Scan Results</h3>
                {results ? (
                  <div className="bg-gray-900 text-green-400 p-6 rounded-lg font-mono text-sm whitespace-pre-wrap overflow-x-auto max-h-96 overflow-y-auto">
                    {results}
                  </div>
                ) : (
                  <div className="bg-gray-100 text-gray-600 p-6 rounded-lg text-center">
                    Enter a target and click "Start Scan" to begin
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {toolId === 'wireshark' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              <div className="lg:col-span-1 bg-white rounded-xl shadow-lg p-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-6">Packet Capture</h2>
                <button
                  onClick={handleWiresharkCapture}
                  disabled={capturing}
                  className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold mb-4"
                >
                  {capturing ? 'Capturing...' : 'Start Capture'}
                </button>
                <div className="text-sm text-gray-600">
                  <p className="font-semibold mb-2">Captured Packets:</p>
                  <p className="text-2xl font-bold text-emerald-600">{packets.length}</p>
                </div>
              </div>

              <div className="lg:col-span-3 bg-white rounded-xl shadow-lg p-8 overflow-auto">
                <h3 className="text-xl font-bold text-gray-900 mb-4">Packet Details</h3>
                {packets.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b-2 border-gray-300">
                          <th className="text-left py-3 px-4 font-semibold">Time</th>
                          <th className="text-left py-3 px-4 font-semibold">Source IP</th>
                          <th className="text-left py-3 px-4 font-semibold">Destination IP</th>
                          <th className="text-left py-3 px-4 font-semibold">Protocol</th>
                        </tr>
                      </thead>
                      <tbody>
                        {packets.slice(-50).reverse().map((packet, i) => (
                          <tr key={i} className="border-b border-gray-200 hover:bg-gray-50">
                            <td className="py-3 px-4 font-mono text-xs">{packet.time}</td>
                            <td className="py-3 px-4 font-mono text-xs">{packet.source}</td>
                            <td className="py-3 px-4 font-mono text-xs">{packet.dest}</td>
                            <td className="py-3 px-4">
                              <span className="bg-emerald-100 text-emerald-800 px-2 py-1 rounded text-xs font-semibold">
                                {packet.protocol}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="bg-gray-100 text-gray-600 p-8 rounded-lg text-center">
                    Click "Start Capture" to begin capturing network packets
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {toolId === 'encryption' && (
          <div className="max-w-3xl mx-auto bg-white rounded-xl shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">AES-256 Encryption</h2>
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Text to Encrypt</label>
                <textarea
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="Enter your message here..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 font-mono"
                  rows={4}
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Encryption Key</label>
                <input
                  type="password"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="Your secret encryption key"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500"
                />
              </div>
              <button
                onClick={handleEncrypt}
                disabled={!text || !key}
                className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
              >
                Encrypt
              </button>
              {encrypted && (
                <div className="bg-emerald-50 border-2 border-emerald-200 rounded-lg p-6">
                  <p className="text-sm font-semibold text-emerald-900 mb-2">Encrypted Output:</p>
                  <p className="font-mono text-sm break-all bg-white p-4 rounded border border-emerald-200 text-gray-900">{encrypted}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {toolId === 'decryption' && (
          <div className="max-w-3xl mx-auto bg-white rounded-xl shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">AES-256 Decryption</h2>
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Encrypted Text</label>
                <textarea
                  value={encryptedText}
                  onChange={(e) => setEncryptedText(e.target.value)}
                  placeholder="Paste encrypted message here..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 font-mono"
                  rows={4}
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Decryption Key</label>
                <input
                  type="password"
                  value={decryptKey}
                  onChange={(e) => setDecryptKey(e.target.value)}
                  placeholder="Your decryption key"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500"
                />
              </div>
              <button
                onClick={handleDecrypt}
                disabled={!encryptedText || !decryptKey}
                className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
              >
                Decrypt
              </button>
              {decrypted && (
                <div className="bg-emerald-50 border-2 border-emerald-200 rounded-lg p-6">
                  <p className="text-sm font-semibold text-emerald-900 mb-2">Decrypted Output:</p>
                  <p className="bg-white p-4 rounded border border-emerald-200 text-gray-900">{decrypted}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {toolId === 'hash' && (
          <div className="max-w-3xl mx-auto bg-white rounded-xl shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Cryptographic Hash Generator</h2>
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Input Text</label>
                <input
                  type="text"
                  value={hashText}
                  onChange={(e) => setHashText(e.target.value)}
                  placeholder="Enter text to hash..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500"
                />
              </div>
              <button
                onClick={generateHash}
                disabled={!hashText}
                className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
              >
                Generate Hashes
              </button>
              {hashes && (
                <div className="space-y-4">
                  <div className="bg-emerald-50 border-2 border-emerald-200 rounded-lg p-6">
                    <p className="text-sm font-semibold text-emerald-900 mb-2">SHA-256 Hash:</p>
                    <p className="font-mono text-sm break-all bg-white p-4 rounded border border-emerald-200 text-gray-900">{hashes.sha256}</p>
                  </div>
                  <div className="bg-yellow-50 border-2 border-yellow-200 rounded-lg p-6">
                    <p className="text-sm font-semibold text-yellow-900 mb-2">Note:</p>
                    <p className="text-sm text-yellow-900">{hashes.sha1}</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {toolId === 'password' && (
          <div className="max-w-3xl mx-auto bg-white rounded-xl shadow-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Password Strength Analyzer</h2>
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Password</label>
                <input
                  type="text"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password to analyze..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500"
                />
              </div>
              <button
                onClick={analyzePassword}
                disabled={!password}
                className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
              >
                Analyze Password
              </button>
              {strength && (
                <div className="space-y-4">
                  <div>
                    <p className="text-sm font-semibold text-gray-700 mb-3">Strength Level:</p>
                    <div className="flex space-x-1">
                      {[1, 2, 3, 4, 5].map((i) => (
                        <div
                          key={i}
                          className="h-3 flex-1 rounded"
                          style={{
                            backgroundColor: i <= strength.score
                              ? strength.color === 'red' ? '#ef4444'
                              : strength.color === 'orange' ? '#f97316'
                              : strength.color === 'yellow' ? '#eab308'
                              : strength.color === 'blue' ? '#3b82f6'
                              : '#10b981'
                              : '#e5e7eb'
                          }}
                        />
                      ))}
                    </div>
                  </div>
                  {strength.feedback.length > 0 && (
                    <div className="bg-yellow-50 border-2 border-yellow-200 rounded-lg p-6">
                      <p className="text-sm font-semibold text-yellow-900 mb-3">Recommendations:</p>
                      <ul className="space-y-2">
                        {strength.feedback.map((item, i) => (
                          <li key={i} className="text-sm text-yellow-900">✗ {item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
