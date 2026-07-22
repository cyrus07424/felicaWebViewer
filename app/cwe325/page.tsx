'use client';

import { useState, useCallback } from 'react';

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

async function pbkdf2Hex(password: string, salt: string): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
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

type HashEntry = {
  password: string;
  salt?: string;
  hash: string;
};

// ---- Component ----

export default function Cwe325Demo() {
  const [password, setPassword] = useState('');
  const [vulnerableEntries, setVulnerableEntries] = useState<HashEntry[]>([]);
  const [secureEntries, setSecureEntries] = useState<HashEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAdd = useCallback(async () => {
    if (!password) return;
    setLoading(true);
    setError(null);
    try {
      const salt = generateSalt();
      const [unsaltedHash, saltedHash] = await Promise.all([
        sha256Hex(password),
        pbkdf2Hex(password, salt),
      ]);
      setVulnerableEntries((prev) => [
        ...prev,
        { password, hash: unsaltedHash },
      ]);
      setSecureEntries((prev) => [
        ...prev,
        { password, salt, hash: saltedHash },
      ]);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'ハッシュ計算中にエラーが発生しました。Web Crypto API が利用可能か確認してください。'
      );
    } finally {
      setLoading(false);
    }
  }, [password]);

  const handleClear = useCallback(() => {
    setVulnerableEntries([]);
    setSecureEntries([]);
    setPassword('');
  }, []);

  // Highlight rows where the same password was stored more than once — O(n)
  const passwordCount = new Map<string, number>();
  for (const entry of vulnerableEntries) {
    passwordCount.set(entry.password, (passwordCount.get(entry.password) ?? 0) + 1);
  }
  const vulnerableDuplicates = new Set<number>(
    vulnerableEntries
      .map((entry, i) => ((passwordCount.get(entry.password) ?? 0) > 1 ? i : -1))
      .filter((i) => i !== -1)
  );

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
            パスワードをハッシュ化する際に <strong>ソルト (salt)</strong>{' '}
            を付与しないと、同一パスワードは常に同一ハッシュ値になります。
            攻撃者は事前計算済みのレインボーテーブルを使ってハッシュから元のパスワードを逆引きできてしまいます。
          </p>
          <ul className="list-disc list-inside space-y-1">
            <li>
              <span className="text-red-600 font-medium">脆弱な実装</span>:
              SHA-256(<em>パスワード</em>) — ソルトなし
            </li>
            <li>
              <span className="text-green-600 font-medium">安全な実装</span>:
              PBKDF2(<em>パスワード</em>, <em>ランダムソルト</em>, 100,000回)
              — ソルトあり
            </li>
          </ul>
        </section>

        {/* Input */}
        <div className="flex gap-2 mb-6">
          <input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
            placeholder="パスワードを入力 (例: password123)"
            className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button
            onClick={handleAdd}
            disabled={loading || !password}
            className="bg-blue-600 text-white px-4 py-2 rounded text-sm font-medium disabled:opacity-50 hover:bg-blue-700 transition-colors"
          >
            {loading ? '計算中…' : '追加'}
          </button>
          <button
            onClick={handleClear}
            className="bg-gray-200 text-gray-700 px-4 py-2 rounded text-sm font-medium hover:bg-gray-300 transition-colors"
          >
            クリア
          </button>
        </div>

        {/* Error */}
        {error && (
          <p className="mb-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
            ⚠️ {error}
          </p>
        )}

        {/* Tip: same password */}
        <p className="text-xs text-gray-500 mb-4">
          💡 同じパスワードを複数回追加して、左右の違いを比較してみましょう。
        </p>

        {/* Tables side-by-side */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Vulnerable */}
          <div>
            <h2 className="text-base font-semibold text-red-600 mb-2 flex items-center gap-1">
              ❌ 脆弱な実装 (ソルトなし SHA-256)
            </h2>
            <div className="overflow-x-auto rounded-lg border border-red-200">
              <table className="w-full text-xs">
                <thead className="bg-red-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-red-700 font-medium">
                      パスワード
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
                        vulnerableDuplicates.has(i)
                          ? 'bg-red-100'
                          : 'bg-white'
                      }
                    >
                      <td className="px-3 py-2 font-mono break-all">
                        {entry.password}
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
                ⚠️ 同じパスワードが同じハッシュ値になっています。
                レインボーテーブルで逆引き可能です。
              </p>
            )}
          </div>

          {/* Secure */}
          <div>
            <h2 className="text-base font-semibold text-green-600 mb-2 flex items-center gap-1">
              ✅ 安全な実装 (ソルトあり PBKDF2)
            </h2>
            <div className="overflow-x-auto rounded-lg border border-green-200">
              <table className="w-full text-xs">
                <thead className="bg-green-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-green-700 font-medium">
                      パスワード
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
                        {entry.password}
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
            {passwordCount.size < secureEntries.length && (
              <p className="mt-2 text-xs text-green-600">
                ✅ 同じパスワードでも、ソルトが異なるためハッシュ値も異なります。
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
              攻撃者がデータベースから <strong>ソルトなしハッシュ</strong>{' '}
              を入手する。
            </li>
            <li>
              事前計算済みのレインボーテーブル（SHA-256 版）を使ってハッシュを逆引きする。
            </li>
            <li>元のパスワードが判明し、不正ログインに悪用される。</li>
          </ol>
          <p className="mt-3">
            <strong>対策</strong>:{' '}
            PBKDF2・bcrypt・scrypt・Argon2 など、ソルト付き鍵導出関数を使用する。
            ソルトは認証情報ごとにランダムに生成し、ハッシュと一緒に保存する。
          </p>
        </section>

        <p className="mt-6 text-xs text-gray-400 text-center">
          ※ このページは教育・デモ目的で作成されています。実際のパスワードは入力しないでください。
        </p>
      </div>
    </main>
  );
}
