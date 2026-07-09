'use client';

import { useState, useCallback, useRef } from 'react';
import { RCS380, ReceivedPacket } from 'rc_s380_driver';

// FeliCa 212kbps RF settings (TX: F212, RX: F212)
const FELICA_RF = Uint8Array.of(0x01, 0x01);
// FeliCa protocol settings (initial guard time, ADD_CRC | CHECK_CRC)
const FELICA_PROTOCOL = Uint8Array.of(0x01, 0x00, 0x02, 0x07);

// Polling interval (ms)
const POLL_INTERVAL_MS = 300;
// Polling timeout (s)
const POLL_TIMEOUT_S = 0.5;

type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'scanning'
  | 'error';

type CardInfo = {
  idm: string;
  pmm: string;
  systemCode: string;
  detectedAt: Date;
};

function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function identifySystemCode(code: string): string {
  const map: Record<string, string> = {
    '88 B4': '交通系ICカード（Suica / PASMO / TOICA 等）',
    '88 F1': 'Edy（電子マネー）',
    '00 03': 'FeliCa Lite',
    '80 0B': 'iD',
    '80 4B': 'QUICPay',
  };
  return map[code] ?? '不明なシステム';
}

export default function FelicaReader() {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [error, setError] = useState<string | null>(null);
  const [card, setCard] = useState<CardInfo | null>(null);
  const rcs380Ref = useRef<RCS380 | null>(null);
  const scanningRef = useRef(false);

  const startScanning = useCallback(async (rcs380: RCS380) => {
    scanningRef.current = true;
    setStatus('scanning');

    while (scanningRef.current) {
      try {
        // FeliCa polling command: [len, 0x04, sysHigh, sysLow, requestCode, timeSlot]
        // requestCode=0x01 → response includes system code
        const pollingCmd = Uint8Array.of(0x06, 0x04, 0xff, 0xff, 0x01, 0x00);
        const result: ReceivedPacket = await rcs380.inCommRf(
          pollingCmd,
          POLL_TIMEOUT_S
        );

        const data = result.data;
        // Success response: [len(1), 0x05(1), IDm(8), PMm(8), systemCode(2)] = 20 bytes min
        if (data.length >= 19 && data[1] === 0x05) {
          const idm = data.slice(2, 10);
          const pmm = data.slice(10, 18);
          const systemCode = data.length >= 20 ? data.slice(18, 20) : null;

          setCard({
            idm: toHex(idm),
            pmm: toHex(pmm),
            systemCode: systemCode ? toHex(systemCode) : '不明',
            detectedAt: new Date(),
          });
        }
      } catch {
        // Timeout or no card — clear card display and keep polling
        setCard(null);
      }

      await new Promise<void>((resolve) =>
        setTimeout(resolve, POLL_INTERVAL_MS)
      );
    }
  }, []);

  const handleConnect = useCallback(async () => {
    try {
      setStatus('connecting');
      setError(null);
      setCard(null);

      const rcs380 = await RCS380.connect();
      rcs380Ref.current = rcs380;

      await rcs380.initDevice();
      await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);

      await startScanning(rcs380);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'エラーが発生しました';
      setError(message);
      setStatus('error');
    }
  }, [startScanning]);

  const handleDisconnect = useCallback(async () => {
    scanningRef.current = false;
    try {
      if (rcs380Ref.current) {
        await rcs380Ref.current.disconnect();
      }
    } finally {
      rcs380Ref.current = null;
      setStatus('disconnected');
      setCard(null);
      setError(null);
    }
  }, []);

  const isConnected = status === 'scanning';

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/60 backdrop-blur px-6 py-4">
        <div className="mx-auto flex max-w-3xl items-center gap-3">
          <span className="text-3xl">📡</span>
          <div>
            <h1 className="text-xl font-bold tracking-wide">
              FeliCa Web Viewer
            </h1>
            <p className="text-sm text-slate-400">
              RC-S380 を使用した FeliCa カードリーダー
            </p>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-6 py-10 space-y-8">
        {/* Instructions */}
        <section className="rounded-2xl bg-slate-800/60 border border-slate-700 p-6 text-center space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">
            システムについて
          </h2>
          <p className="text-slate-300 leading-relaxed">
            このアプリは WebUSB を使用して Sony RC-S380 NFC
            リーダーに接続し、かざされた FeliCa
            カードの情報を読み取り、画面に表示します。
          </p>

          <div className="rounded-xl bg-slate-900/60 border border-slate-600 p-4 text-left text-sm text-slate-300 space-y-2">
            <p className="font-semibold text-slate-100">📋 操作手順</p>
            <ol className="list-decimal list-inside space-y-1 marker:text-blue-400">
              <li>
                RC-S380 を PC の USB ポートに接続してください。
              </li>
              <li>
                下の <span className="font-semibold text-blue-300">「接続」</span>{' '}
                ボタンをクリックし、表示されたダイアログで RC-S380
                を選択してください。
              </li>
              <li>
                リーダーに FeliCa
                カードをかざすと、カード情報が表示されます。
              </li>
              <li>
                終了する場合は <span className="font-semibold text-red-300">「切断」</span>{' '}
                ボタンをクリックしてください。
              </li>
            </ol>
          </div>

          <div className="rounded-xl bg-amber-900/30 border border-amber-600/40 p-3 text-sm text-amber-300">
            ⚠ WebUSB はChrome / Edge などの Chromium 系ブラウザでのみ動作します。
          </div>
        </section>

        {/* Connection control */}
        <section className="flex flex-col items-center gap-4">
          {!isConnected ? (
            <button
              onClick={handleConnect}
              disabled={status === 'connecting'}
              className="rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed px-10 py-3 font-semibold text-lg transition-colors shadow-lg shadow-blue-900/40"
            >
              {status === 'connecting' ? (
                <span className="flex items-center gap-2">
                  <span className="animate-spin">⟳</span> 接続中…
                </span>
              ) : (
                '接続'
              )}
            </button>
          ) : (
            <button
              onClick={handleDisconnect}
              className="rounded-xl bg-red-600 hover:bg-red-500 px-10 py-3 font-semibold text-lg transition-colors shadow-lg shadow-red-900/40"
            >
              切断
            </button>
          )}

          {/* Status indicator */}
          <div className="flex items-center gap-2 text-sm">
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${
                status === 'scanning'
                  ? 'bg-green-400 animate-pulse'
                  : status === 'connecting'
                  ? 'bg-yellow-400 animate-pulse'
                  : status === 'error'
                  ? 'bg-red-400'
                  : 'bg-slate-500'
              }`}
            />
            <span className="text-slate-300">
              {status === 'scanning'
                ? 'スキャン中 — カードをかざしてください'
                : status === 'connecting'
                ? 'RC-S380 に接続しています…'
                : status === 'error'
                ? 'エラーが発生しました'
                : '未接続'}
            </span>
          </div>

          {error && (
            <div className="rounded-xl bg-red-900/40 border border-red-600/50 px-5 py-3 text-sm text-red-300 max-w-md text-center">
              {error}
            </div>
          )}
        </section>

        {/* Card data */}
        {card && (
          <section className="rounded-2xl bg-slate-800/60 border border-green-600/40 p-6 space-y-5 animate-fade-in">
            <div className="flex items-center gap-2">
              <span className="text-2xl">💳</span>
              <h2 className="text-lg font-semibold text-green-300">
                カード検出
              </h2>
              <span className="ml-auto text-xs text-slate-500">
                {card.detectedAt.toLocaleTimeString('ja-JP')}
              </span>
            </div>

            <div className="grid gap-4">
              <CardField label="IDm（カード識別子）" value={card.idm} />
              <CardField label="PMm（製造者情報）" value={card.pmm} />
              <CardField
                label="システムコード"
                value={card.systemCode}
                note={identifySystemCode(card.systemCode)}
              />
            </div>
          </section>
        )}

        {/* Waiting state */}
        {isConnected && !card && (
          <section className="rounded-2xl border border-dashed border-slate-600 p-10 text-center text-slate-500">
            <p className="text-4xl mb-3">🔍</p>
            <p className="text-sm">カードをリーダーにかざしてください…</p>
          </section>
        )}
      </main>

      <footer className="border-t border-slate-800 py-6 text-center text-sm text-slate-500">
        &copy; 2026{' '}
        <a
          href="https://github.com/cyrus07424"
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-slate-300 underline"
        >
          cyrus
        </a>
      </footer>
    </div>
  );
}

function CardField({
  label,
  value,
  note,
}: {
  label: string;
  value: string;
  note?: string;
}) {
  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-700 px-4 py-3 space-y-1">
      <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">
        {label}
      </p>
      <p className="font-mono text-base text-slate-100 break-all">{value}</p>
      {note && <p className="text-xs text-slate-500">{note}</p>}
    </div>
  );
}
