'use client';

import { useState, useCallback, useRef } from 'react';
import { RCS380, ReceivedPacket } from 'rc_s380_driver';

// FeliCa 212kbps RF settings (TX: F212, RX: F212, SEND=0x0f, RECV=0x01)
const FELICA_RF = Uint8Array.of(0x01, 0x01, 0x0f, 0x01);
// InSetProtocol option for Type-F polling
const FELICA_PROTOCOL = Uint8Array.of(0x00, 0x18);

// Polling interval (ms)
const POLL_INTERVAL_MS = 300;
// Polling timeout (s)
const POLL_TIMEOUT_S = 0.5;
// Polling command variants for RC-S380 / stack differences.
// social-robotics-lab/card-reader-for-RC-S380 の方針を参考に、
// system code を複数試して実機差分を吸収する。
const POLLING_COMMANDS = [
  // Any system code
  Uint8Array.of(0x06, 0x00, 0xff, 0xff, 0x01, 0x00),
  Uint8Array.of(0x00, 0xff, 0xff, 0x01, 0x00),
  // Common Area (nfcpy sample style)
  Uint8Array.of(0x06, 0x00, 0xfe, 0x00, 0x01, 0x00),
  Uint8Array.of(0x00, 0xfe, 0x00, 0x01, 0x00),
  // Transit IC cards (Suica / PASMO etc.)
  Uint8Array.of(0x06, 0x00, 0x88, 0xb4, 0x01, 0x00),
  Uint8Array.of(0x00, 0x88, 0xb4, 0x01, 0x00),
];

type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'scanning'
  | 'error';

type CardInfo = {
  idm: string;
  pmm: string;
  systemCode: string;
  cardMode?: string;
  availableSystemCodes?: string[];
  detectedAt: Date;
};

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return 'エラーが発生しました';
}

function toDisplayError(message: string): string {
  if (
    message.includes("Failed to execute 'open' on 'USBDevice': Access denied.")
  ) {
    return [
      'RC-S380 へのアクセスが拒否されました。',
      '他アプリ（NFCポートソフト、カードビューア、e-Tax関連ソフト等）を終了してから再試行してください。',
      '改善しない場合は RC-S380 を抜き差しし、ブラウザを再起動してください。',
      'Windows 環境では WebUSB で利用できるドライバー設定（WinUSB）が必要です。',
    ].join('\n');
  }

  return message;
}

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

function parseHexBytes(hex: string): Uint8Array {
  const tokens = hex.split(' ').filter(Boolean);
  return Uint8Array.from(tokens.map((token) => Number.parseInt(token, 16)));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function findFelicaPayload(
  data: Uint8Array,
  responseCode: number,
  idm: Uint8Array
): Uint8Array | null {
  for (let i = 0; i <= data.length - (1 + idm.length); i += 1) {
    if (data[i] !== responseCode) {
      continue;
    }
    const candidateIdm = data.slice(i + 1, i + 1 + idm.length);
    if (equalBytes(candidateIdm, idm)) {
      return data.slice(i);
    }
  }
  return null;
}

function parseCardMode(mode: number): string {
  const modeMap: Record<number, string> = {
    0x00: '通常モード',
    0x01: '認証モード',
  };
  const label = modeMap[mode] ?? '不明';
  return `0x${mode.toString(16).padStart(2, '0').toUpperCase()} (${label})`;
}

function parsePollingResponse(data: Uint8Array): CardInfo | null {
  // RC-S380 InCommRF wrapped response:
  // [0xD7, 0x05, status, ..., pollingResponse]
  if (data.length >= 17 && data[0] === 0xd7 && data[1] === 0x05) {
    if (data[2] !== 0x00) {
      return null;
    }
    if (data.length >= 25 && data[8] === 0x01) {
      const idm = data.slice(9, 17);
      const pmm = data.slice(17, 25);
      const systemCode = data.length >= 27 ? data.slice(25, 27) : null;

      return {
        idm: toHex(idm),
        pmm: toHex(pmm),
        systemCode: systemCode ? toHex(systemCode) : '不明',
        detectedAt: new Date(),
      };
    }
  }

  // Supported forms:
  // [0x01, IDm(8), PMm(8), systemCode(2)]
  // [len(1), 0x01, IDm(8), PMm(8), systemCode(2)]
  const pollingResponse =
    data.length >= 17 && data[0] === 0x01
      ? data
      : data.length >= 18 && data[1] === 0x01
      ? data.slice(1)
      : null;

  if (!pollingResponse || pollingResponse.length < 17) {
    return null;
  }

  const idm = pollingResponse.slice(1, 9);
  const pmm = pollingResponse.slice(9, 17);
  const systemCode =
    pollingResponse.length >= 19 ? pollingResponse.slice(17, 19) : null;

  return {
    idm: toHex(idm),
    pmm: toHex(pmm),
    systemCode: systemCode ? toHex(systemCode) : '不明',
    detectedAt: new Date(),
  };
}

export default function FelicaReader() {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [error, setError] = useState<string | null>(null);
  const [card, setCard] = useState<CardInfo | null>(null);
  const rcs380Ref = useRef<RCS380 | null>(null);
  const scanningRef = useRef(false);
  const lastDetectedIdmRef = useRef<string | null>(null);

  const shutdownDevice = useCallback(async (rcs380: RCS380) => {
    let disconnectError: unknown = null;
    try {
      await rcs380.disconnect();
    } catch (err) {
      disconnectError = err;
    }

    if (rcs380.device.opened) {
      await rcs380.device.close();
    }

    if (disconnectError) {
      throw disconnectError;
    }
  }, []);

  const startScanning = useCallback(async (rcs380: RCS380) => {
    scanningRef.current = true;
    setStatus('scanning');

    while (scanningRef.current) {
      let detectedCard: CardInfo | null = null;

      for (const pollingCmd of POLLING_COMMANDS) {
        try {
          const result: ReceivedPacket = await rcs380.inCommRf(
            pollingCmd,
            POLL_TIMEOUT_S
          );
          detectedCard = parsePollingResponse(result.data);
          if (detectedCard) {
            break;
          }
        } catch {
          // Try next polling variant.
        }
      }

      if (detectedCard) {
        const isNewCard = lastDetectedIdmRef.current !== detectedCard.idm;
        lastDetectedIdmRef.current = detectedCard.idm;

        if (isNewCard) {
          const idmBytes = parseHexBytes(detectedCard.idm);
          let cardMode: string | undefined;
          let availableSystemCodes: string[] | undefined;

          try {
            const modeRequest = Uint8Array.of(0x04, ...idmBytes);
            const modeResult = await rcs380.inCommRf(modeRequest, POLL_TIMEOUT_S);
            const modePayload = findFelicaPayload(modeResult.data, 0x05, idmBytes);
            if (modePayload && modePayload.length >= 10) {
              cardMode = parseCardMode(modePayload[9]);
            }
          } catch {
            // Keep polling even when optional details are unavailable.
          }

          try {
            const systemCodeRequest = Uint8Array.of(0x0c, ...idmBytes);
            const systemCodeResult = await rcs380.inCommRf(
              systemCodeRequest,
              POLL_TIMEOUT_S
            );
            const systemCodePayload = findFelicaPayload(
              systemCodeResult.data,
              0x0d,
              idmBytes
            );
            if (systemCodePayload && systemCodePayload.length >= 10) {
              const count = systemCodePayload[9];
              const codes: string[] = [];
              for (let i = 0; i < count; i += 1) {
                const offset = 10 + i * 2;
                if (offset + 1 < systemCodePayload.length) {
                  codes.push(
                    toHex(Uint8Array.of(systemCodePayload[offset], systemCodePayload[offset + 1]))
                  );
                }
              }
              if (codes.length > 0) {
                availableSystemCodes = codes;
              }
            }
          } catch {
            // Keep polling even when optional details are unavailable.
          }

          setCard({
            ...detectedCard,
            cardMode,
            availableSystemCodes,
            detectedAt: new Date(),
          });
        } else {
          setCard((prev) =>
            prev
              ? {
                  ...prev,
                  detectedAt: new Date(),
                }
              : detectedCard
          );
        }
      } else {
        // Timeout or no card — clear card display and keep polling
        lastDetectedIdmRef.current = null;
        setCard(null);
      }

      await new Promise<void>((resolve) =>
        setTimeout(resolve, POLL_INTERVAL_MS)
      );
    }
  }, []);

  const handleConnect = useCallback(async () => {
    let connectedReader: RCS380 | null = null;
    try {
      setStatus('connecting');
      setError(null);
      setCard(null);
      lastDetectedIdmRef.current = null;

      const rcs380 = await RCS380.connect();
      connectedReader = rcs380;
      rcs380Ref.current = rcs380;

      await rcs380.initDevice();
      await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);

      await startScanning(rcs380);
    } catch (err) {
      let cleanupError: unknown = null;
      if (connectedReader) {
        try {
          await shutdownDevice(connectedReader);
        } catch (cleanupErr) {
          cleanupError = cleanupErr;
        }
      }

      rcs380Ref.current = null;
      const errorMessage = toDisplayError(getErrorMessage(err));
      const cleanupMessage = cleanupError
        ? `\nデバイス解放中にエラー: ${getErrorMessage(cleanupError)}`
        : '';
      setError(`${errorMessage}${cleanupMessage}`);
      setStatus('error');
    }
  }, [shutdownDevice, startScanning]);

  const handleDisconnect = useCallback(async () => {
    scanningRef.current = false;
    const currentReader = rcs380Ref.current;
    rcs380Ref.current = null;

    if (!currentReader) {
      setStatus('disconnected');
      setCard(null);
      setError(null);
      lastDetectedIdmRef.current = null;
      return;
    }

    try {
      await shutdownDevice(currentReader);
      setStatus('disconnected');
      setCard(null);
      setError(null);
      lastDetectedIdmRef.current = null;
    } catch (err) {
      setStatus('error');
      setError(toDisplayError(getErrorMessage(err)));
    }
  }, [shutdownDevice]);

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
            <br />
            ⚠ 「Access denied」が出る場合は、RC-S380 を使用中の他アプリを終了してください。
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
              {card.cardMode && (
                <CardField label="カードモード" value={card.cardMode} />
              )}
              {card.availableSystemCodes && card.availableSystemCodes.length > 0 && (
                <CardField
                  label="利用可能システムコード"
                  value={card.availableSystemCodes.join(' / ')}
                />
              )}
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
