'use client';

import { useState, useCallback, useRef } from 'react';
import { RCS380, ReceivedPacket } from 'rc_s380_driver';

// ---- RC-S380 constants (same as FelicaReader) ----

const FELICA_RF = Uint8Array.of(0x01, 0x01, 0x0f, 0x01);
const FELICA_PROTOCOL = Uint8Array.of(0x00, 0x18);
const POLL_TIMEOUT_S = 0.5;
const POLL_INTERVAL_MS = 300;
const POLLING_COMMANDS = [
  Uint8Array.of(0x06, 0x00, 0xff, 0xff, 0x01, 0x00),
  Uint8Array.of(0x00, 0xff, 0xff, 0x01, 0x00),
  Uint8Array.of(0x06, 0x00, 0xff, 0xff, 0x00, 0x00),
  Uint8Array.of(0x00, 0xff, 0xff, 0x00, 0x00),
  Uint8Array.of(0x06, 0x00, 0xfe, 0x00, 0x01, 0x00),
  Uint8Array.of(0x00, 0xfe, 0x00, 0x01, 0x00),
  Uint8Array.of(0x06, 0x00, 0x88, 0xb4, 0x01, 0x00),
  Uint8Array.of(0x00, 0x88, 0xb4, 0x01, 0x00),
];

// ---- RC-S380 helpers ----

function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function parsePollingResponse(data: Uint8Array): string | null {
  if (data.length >= 17 && data[0] === 0xd7 && data[1] === 0x05) {
    if (data[2] !== 0x00) return null;
    if (data.length >= 25 && data[8] === 0x01) {
      return toHex(data.slice(9, 17));
    }
  }
  const pollingResponse =
    data.length >= 17 && data[0] === 0x01
      ? data
      : data.length >= 18 && data[1] === 0x01
      ? data.slice(1)
      : null;
  if (!pollingResponse || pollingResponse.length < 17) return null;
  return toHex(pollingResponse.slice(1, 9));
}

function getErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'エラーが発生しました';
}

function toDisplayError(message: string): string {
  if (message.includes("Failed to execute 'open' on 'USBDevice': Access denied.")) {
    return [
      'RC-S380 へのアクセスが拒否されました。',
      '他アプリ（NFCポートソフト等）を終了してから再試行してください。',
      '改善しない場合は RC-S380 を抜き差しし、ブラウザを再起動してください。',
      'Windows 環境では WebUSB で利用できるドライバー設定（WinUSB）が必要です。',
    ].join('\n');
  }
  return message;
}

// ---- Crypto helpers (Web Crypto API) ----

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateSalt(byteLength = 16): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function pbkdf2Hex(data: string, salt: string): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(data),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(salt),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---- Types ----

type ConnectionStatus = 'disconnected' | 'connecting' | 'scanning' | 'error';

type HashEntry = {
  idm: string;
  salt?: string;
  hash: string;
};

// ---- Component ----

export default function Cwe325Demo() {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [connError, setConnError] = useState<string | null>(null);
  const rcs380Ref = useRef<RCS380 | null>(null);
  const scanningRef = useRef(false);
  const lastDetectedIdmRef = useRef<string | null>(null);

  const [manualIdm, setManualIdm] = useState('');
  const [hashError, setHashError] = useState<string | null>(null);
  const [vulnerableEntries, setVulnerableEntries] = useState<HashEntry[]>([]);
  const [secureEntries, setSecureEntries] = useState<HashEntry[]>([]);

  const addEntry = useCallback(async (idm: string) => {
    setHashError(null);
    try {
      const salt = generateSalt();
      const [unsaltedHash, saltedHash] = await Promise.all([
        sha256Hex(idm),
        pbkdf2Hex(idm, salt),
      ]);
      setVulnerableEntries((prev) => [...prev, { idm, hash: unsaltedHash }]);
      setSecureEntries((prev) => [...prev, { idm, salt, hash: saltedHash }]);
    } catch (err) {
      setHashError(
        err instanceof Error
          ? err.message
          : 'ハッシュ計算中にエラーが発生しました。'
      );
    }
  }, []);

  const startScanning = useCallback(
    async (rcs380: RCS380) => {
      scanningRef.current = true;
      setStatus('scanning');
      await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);

      while (scanningRef.current) {
        let detectedIdm: string | null = null;

        for (const pollingCmd of POLLING_COMMANDS) {
          try {
            const result: ReceivedPacket = await rcs380.inCommRf(
              pollingCmd,
              POLL_TIMEOUT_S
            );
            const idm = parsePollingResponse(result.data);
            if (idm) {
              detectedIdm = idm;
              break;
            }
          } catch {
            // Try next polling variant.
          }
        }

        if (detectedIdm && detectedIdm !== lastDetectedIdmRef.current) {
          lastDetectedIdmRef.current = detectedIdm;
          await addEntry(detectedIdm);
        } else if (!detectedIdm) {
          lastDetectedIdmRef.current = null;
        }

        await new Promise<void>((resolve) =>
          setTimeout(resolve, POLL_INTERVAL_MS)
        );
      }
    },
    [addEntry]
  );

  const handleConnect = useCallback(async () => {
    let connectedReader: RCS380 | null = null;
    try {
      setStatus('connecting');
      setConnError(null);
      lastDetectedIdmRef.current = null;

      const rcs380 = await RCS380.connect();
      connectedReader = rcs380;
      rcs380Ref.current = rcs380;

      await rcs380.initDevice();
      await startScanning(rcs380);
    } catch (err) {
      if (connectedReader) {
        try {
          await connectedReader.disconnect();
        } catch {
          // Ignore cleanup errors.
        }
        try {
          if (connectedReader.device.opened) {
            await connectedReader.device.close();
          }
        } catch {
          // Ignore cleanup errors.
        }
      }
      rcs380Ref.current = null;
      setConnError(toDisplayError(getErrorMessage(err)));
      setStatus('error');
    }
  }, [startScanning]);

  const handleDisconnect = useCallback(async () => {
    scanningRef.current = false;
    const currentReader = rcs380Ref.current;
    rcs380Ref.current = null;

    if (!currentReader) {
      setStatus('disconnected');
      return;
    }

    try {
      await currentReader.disconnect();
    } catch {
      // Ignore disconnect errors.
    }
    try {
      if (currentReader.device.opened) {
        await currentReader.device.close();
      }
    } catch {
      // Ignore close errors.
    }
    setStatus('disconnected');
  }, []);

  const handleManualAdd = useCallback(async () => {
    const idm = manualIdm.trim();
    if (!idm) return;
    await addEntry(idm);
    setManualIdm('');
  }, [manualIdm, addEntry]);

  const handleClear = useCallback(() => {
    setVulnerableEntries([]);
    setSecureEntries([]);
  }, []);

  // O(n) duplicate detection for vulnerable table
  const idmCount = new Map<string, number>();
  for (const entry of vulnerableEntries) {
    idmCount.set(entry.idm, (idmCount.get(entry.idm) ?? 0) + 1);
  }
  const vulnerableDuplicates = new Set<number>(
    vulnerableEntries
      .map((entry, i) => ((idmCount.get(entry.idm) ?? 0) > 1 ? i : -1))
      .filter((i) => i !== -1)
  );

  const isScanning = status === 'scanning';
  const isConnecting = status === 'connecting';

  return (
    <main className="min-h-screen bg-gray-50 p-6 font-sans">
      <div className="mx-auto max-w-5xl">
        {/* Header */}
        <h1 className="text-2xl font-bold text-gray-800 mb-1">
          CWE-325 デモ: 暗号化ステップの欠落 (Missing Cryptographic Step)
        </h1>
        <p className="text-sm text-gray-500 mb-4">
          参考:{' '}
          <a
            href="https://cwe.mitre.org/data/definitions/325.html"
            target="_blank"
            rel="noopener noreferrer"
            className="underline text-blue-600"
          >
            https://cwe.mitre.org/data/definitions/325.html
          </a>
        </p>

        {/* Explanation */}
        <section className="bg-white border border-gray-200 rounded-lg p-4 mb-6 text-sm text-gray-700 leading-relaxed">
          <h2 className="font-semibold text-base text-gray-800 mb-2">
            脆弱性の概要
          </h2>
          <p className="mb-2">
            FeliCa カードの <strong>IDm（カード識別子）</strong>{' '}
            をハッシュ化してデータベースに保存する際に{' '}
            <strong>ソルト (salt)</strong>{' '}
            を付与しないと、同一カードは常に同一ハッシュ値になります。
            攻撃者は事前計算済みのレインボーテーブルを使ってハッシュから元の IDm
            を逆引きし、カードを偽造・なりすましに悪用できます。
          </p>
          <ul className="list-disc list-inside space-y-1">
            <li>
              <span className="text-red-600 font-medium">脆弱な実装</span>:
              SHA-256(<em>IDm</em>) — ソルトなし
            </li>
            <li>
              <span className="text-green-600 font-medium">安全な実装</span>:
              PBKDF2(<em>IDm</em>, <em>ランダムソルト</em>, 100,000回)
              — ソルトあり
            </li>
          </ul>
        </section>

        {/* RC-S380 Connection */}
        <section className="bg-white border border-gray-200 rounded-lg p-4 mb-6">
          <h2 className="font-semibold text-base text-gray-800 mb-3">
            RC-S380 接続
          </h2>
          <div className="flex items-center gap-3 flex-wrap">
            {!isScanning && !isConnecting && (
              <button
                onClick={handleConnect}
                className="bg-blue-600 text-white px-4 py-2 rounded text-sm font-medium hover:bg-blue-700 transition-colors"
              >
                🔌 RC-S380 に接続
              </button>
            )}
            {isConnecting && (
              <span className="text-sm text-blue-600 font-medium animate-pulse">
                接続中…
              </span>
            )}
            {isScanning && (
              <>
                <span className="text-sm text-green-600 font-medium flex items-center gap-1">
                  <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                  スキャン中 — カードをリーダーにかざしてください
                </span>
                <button
                  onClick={handleDisconnect}
                  className="bg-gray-200 text-gray-700 px-3 py-2 rounded text-sm font-medium hover:bg-gray-300 transition-colors"
                >
                  切断
                </button>
              </>
            )}
            {status === 'error' && (
              <button
                onClick={handleConnect}
                className="bg-blue-600 text-white px-4 py-2 rounded text-sm font-medium hover:bg-blue-700 transition-colors"
              >
                再接続
              </button>
            )}
          </div>
          {connError && (
            <pre className="mt-3 text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2 whitespace-pre-wrap">
              ⚠️ {connError}
            </pre>
          )}
        </section>

        {/* Manual IDm input (fallback) */}
        <section className="bg-white border border-gray-200 rounded-lg p-4 mb-4">
          <h2 className="font-semibold text-sm text-gray-600 mb-2">
            手動入力 (RC-S380 がない場合のデモ用)
          </h2>
          <div className="flex gap-2">
            <input
              type="text"
              value={manualIdm}
              onChange={(e) => setManualIdm(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleManualAdd()}
              placeholder="IDm を手動入力 (例: 01 2E 45 AB CD 12 34 56)"
              className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
            <button
              onClick={handleManualAdd}
              disabled={!manualIdm.trim()}
              className="bg-gray-600 text-white px-4 py-2 rounded text-sm font-medium disabled:opacity-50 hover:bg-gray-700 transition-colors"
            >
              追加
            </button>
            <button
              onClick={handleClear}
              className="bg-gray-200 text-gray-700 px-4 py-2 rounded text-sm font-medium hover:bg-gray-300 transition-colors"
            >
              クリア
            </button>
          </div>
        </section>

        {/* Hash error */}
        {hashError && (
          <p className="mb-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
            ⚠️ {hashError}
          </p>
        )}

        {/* Tip */}
        <p className="text-xs text-gray-500 mb-4">
          💡 同じカードを複数回かざして、左右の違いを比較してみましょう。
        </p>

        {/* Tables side-by-side */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Vulnerable */}
          <div>
            <h2 className="text-base font-semibold text-red-600 mb-2">
              ❌ 脆弱な実装 (ソルトなし SHA-256)
            </h2>
            <div className="overflow-x-auto rounded-lg border border-red-200">
              <table className="w-full text-xs">
                <thead className="bg-red-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-red-700 font-medium">
                      IDm
                    </th>
                    <th className="px-3 py-2 text-left text-red-700 font-medium">
                      ハッシュ値 (SHA-256)
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-red-100">
                  {vulnerableEntries.length === 0 && (
                    <tr>
                      <td
                        colSpan={2}
                        className="px-3 py-4 text-center text-gray-400"
                      >
                        エントリがありません
                      </td>
                    </tr>
                  )}
                  {vulnerableEntries.map((entry, i) => (
                    <tr
                      key={i}
                      className={
                        vulnerableDuplicates.has(i) ? 'bg-red-100' : 'bg-white'
                      }
                    >
                      <td className="px-3 py-2 font-mono break-all">
                        {entry.idm}
                        {vulnerableDuplicates.has(i) && (
                          <span className="ml-1 text-red-600 font-bold">
                            ← 重複!
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 font-mono break-all text-gray-600">
                        {entry.hash}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {vulnerableDuplicates.size > 0 && (
              <p className="mt-2 text-xs text-red-600">
                ⚠️ 同じ IDm が同じハッシュ値になっています。
                レインボーテーブルで逆引き可能です。
              </p>
            )}
          </div>

          {/* Secure */}
          <div>
            <h2 className="text-base font-semibold text-green-600 mb-2">
              ✅ 安全な実装 (ソルトあり PBKDF2)
            </h2>
            <div className="overflow-x-auto rounded-lg border border-green-200">
              <table className="w-full text-xs">
                <thead className="bg-green-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-green-700 font-medium">
                      IDm
                    </th>
                    <th className="px-3 py-2 text-left text-green-700 font-medium">
                      ソルト
                    </th>
                    <th className="px-3 py-2 text-left text-green-700 font-medium">
                      ハッシュ値 (PBKDF2)
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-green-100">
                  {secureEntries.length === 0 && (
                    <tr>
                      <td
                        colSpan={3}
                        className="px-3 py-4 text-center text-gray-400"
                      >
                        エントリがありません
                      </td>
                    </tr>
                  )}
                  {secureEntries.map((entry, i) => (
                    <tr key={i} className="bg-white">
                      <td className="px-3 py-2 font-mono break-all">
                        {entry.idm}
                      </td>
                      <td className="px-3 py-2 font-mono break-all text-gray-500">
                        {entry.salt}
                      </td>
                      <td className="px-3 py-2 font-mono break-all text-gray-600">
                        {entry.hash}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {idmCount.size < secureEntries.length && (
              <p className="mt-2 text-xs text-green-600">
                ✅ 同じ IDm でも、ソルトが異なるためハッシュ値も異なります。
              </p>
            )}
          </div>
        </div>

        {/* Attack explanation */}
        <section className="mt-8 bg-white border border-gray-200 rounded-lg p-4 text-sm text-gray-700 leading-relaxed">
          <h2 className="font-semibold text-base text-gray-800 mb-2">
            攻撃シナリオ
          </h2>
          <ol className="list-decimal list-inside space-y-1">
            <li>
              攻撃者がデータベースから <strong>ソルトなし IDm ハッシュ</strong>{' '}
              を入手する。
            </li>
            <li>
              FeliCa IDm の値空間（8バイト）を総当たりまたはレインボーテーブルで逆引きする。
            </li>
            <li>
              元の IDm が判明し、カードの偽造・なりすましに悪用される。
            </li>
          </ol>
          <p className="mt-3">
            <strong>対策</strong>:{' '}
            PBKDF2・bcrypt・scrypt・Argon2 など、ソルト付き鍵導出関数を使用する。
            ソルトはエントリごとにランダムに生成し、ハッシュと一緒に保存する。
          </p>
        </section>

        <p className="mt-6 text-xs text-gray-400 text-center">
          ※ このページは教育・デモ目的で作成されています。
        </p>
      </div>
    </main>
  );
}
