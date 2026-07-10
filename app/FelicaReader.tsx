'use client';

import { useState, useCallback, useRef } from 'react';
import { RCS380, ReceivedPacket } from 'rc_s380_driver';

// FeliCa 212kbps RF settings (TX: F212, RX: F212, SEND=0x0f, RECV=0x01)
const FELICA_RF = Uint8Array.of(0x01, 0x01, 0x0f, 0x01);
// InSetProtocol option for Type-F polling
const FELICA_PROTOCOL = Uint8Array.of(0x00, 0x18);
// Type A (MIFARE/BanaPassport etc.) settings based on RC-S380 low-level examples
const TYPE_A_RF = Uint8Array.of(0x02, 0x03, 0x0f, 0x03);
const TYPE_A_PROTOCOL = Uint8Array.of(
  0x00,
  0x06,
  0x01,
  0x00,
  0x02,
  0x00,
  0x05,
  0x01,
  0x07,
  0x07
);

// Polling interval (ms)
const POLL_INTERVAL_MS = 300;
const MODE_SWITCH_MISS_THRESHOLD = 3;
// Polling timeout (s)
const POLL_TIMEOUT_S = 0.5;
// Polling command variants for RC-S380 / stack differences.
// social-robotics-lab/card-reader-for-RC-S380 の方針を参考に、
// system code を複数試して実機差分を吸収する。
const POLLING_COMMANDS = [
  // Any system code
  Uint8Array.of(0x06, 0x00, 0xff, 0xff, 0x01, 0x00),
  Uint8Array.of(0x00, 0xff, 0xff, 0x01, 0x00),
  Uint8Array.of(0x06, 0x00, 0xff, 0xff, 0x00, 0x00),
  Uint8Array.of(0x00, 0xff, 0xff, 0x00, 0x00),
  // Common Area (nfcpy sample style)
  Uint8Array.of(0x06, 0x00, 0xfe, 0x00, 0x01, 0x00),
  Uint8Array.of(0x00, 0xfe, 0x00, 0x01, 0x00),
  Uint8Array.of(0x06, 0x00, 0xfe, 0x00, 0x00, 0x00),
  Uint8Array.of(0x00, 0xfe, 0x00, 0x00, 0x00),
  // Transit IC cards (Suica / PASMO etc.)
  Uint8Array.of(0x06, 0x00, 0x88, 0xb4, 0x01, 0x00),
  Uint8Array.of(0x00, 0x88, 0xb4, 0x01, 0x00),
  Uint8Array.of(0x06, 0x00, 0x88, 0xb4, 0x00, 0x00),
  Uint8Array.of(0x00, 0x88, 0xb4, 0x00, 0x00),
];

type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'scanning'
  | 'error';

type CardInfo = {
  cardType?: 'FeliCa' | 'Type A';
  idm: string;
  pmm: string;
  systemCode: string;
  cardMode?: string;
  availableSystemCodes?: string[];
  transitHistory?: TransitHistoryEntry[];
  studentCard?: StudentCardInfo;
  openServices?: OpenServiceEntry[];
  detectedAt: Date;
};

type TransitHistoryEntry = {
  index: number;
  raw: string;
  date: string;
  terminalCode: string;
  processCode: string;
  inStation: string;
  outStation: string;
  balance: number;
  sequence: number;
};

type StudentCardInfo = {
  serviceCode: string;
  studentId?: string;
  issueDate?: string;
  expiryDate?: string;
  blocks: string[];
};

type OpenServiceEntry = {
  serviceCode: string;
  blocks: string[];
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

function unwrapInCommRfData(data: Uint8Array): Uint8Array | null {
  // RC-S380 wrapped response:
  // [0xD7, 0x05, status, ...]
  // Different stacks may place payload at different offsets.
  if (data.length >= 4 && data[0] === 0xd7 && data[1] === 0x05) {
    if (data[2] !== 0x00) {
      return null;
    }

    // Some responses contain [len, ...payload] after status.
    if (data.length >= 5) {
      const declaredLength = data[3];
      if (declaredLength > 0 && data.length >= 4 + declaredLength) {
        return data.slice(4, 4 + declaredLength);
      }
    }

    // Fallback: drop command headers and keep tail bytes.
    return data.slice(4);
  }
  return data;
}

function parseCardMode(mode: number): string {
  const modeMap: Record<number, string> = {
    0x00: '通常モード',
    0x01: '認証モード',
  };
  const label = modeMap[mode] ?? '不明';
  return `0x${mode.toString(16).padStart(2, '0').toUpperCase()} (${label})`;
}

function parseTransitHistoryBlock(
  block: Uint8Array,
  index: number
): TransitHistoryEntry {
  const year = ((block[4] & 0xfe) >> 1) + 2000;
  const month = ((block[4] & 0x01) << 3) | ((block[5] & 0xe0) >> 5);
  const day = block[5] & 0x1f;
  const date = `${year}-${month.toString().padStart(2, '0')}-${day
    .toString()
    .padStart(2, '0')}`;
  const balance = block[10] | (block[11] << 8);
  const sequence = block[12] | (block[13] << 8);
  const inStation = `${block[6].toString(16).padStart(2, '0').toUpperCase()}-${block[7]
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`;
  const outStation = `${block[8].toString(16).padStart(2, '0').toUpperCase()}-${block[9]
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`;

  return {
    index,
    raw: toHex(block),
    date,
    terminalCode: `0x${block[0].toString(16).padStart(2, '0').toUpperCase()}`,
    processCode: `0x${block[1].toString(16).padStart(2, '0').toUpperCase()}`,
    inStation,
    outStation,
    balance,
    sequence,
  };
}

function toServiceCodeLE(serviceCode: number): [number, number] {
  return [serviceCode & 0xff, (serviceCode >> 8) & 0xff];
}

function decodeText(data: Uint8Array): string {
  try {
    return new TextDecoder('shift-jis').decode(data);
  } catch {
    return new TextDecoder().decode(data);
  }
}

function normalizeDate8(value: string): string {
  if (!/^\d{8}$/.test(value)) {
    return value;
  }
  return `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}`;
}

function toServiceCodeHex(serviceCode: number): string {
  return serviceCode.toString(16).padStart(4, '0').toUpperCase();
}

function parseStudentCard(blocks: Uint8Array[]): StudentCardInfo {
  const blockHex = blocks.map((block) => toHex(block));
  const blockText = blocks.map((block) =>
    decodeText(block).replace(/\u0000/g, '').trim()
  );
  const mergedText = blockText.join(' ');
  const studentIdMatch = mergedText.match(/01T[0-9A-Z]{4,12}|[0-9A-Z]{8,14}/);
  const dateMatches = mergedText.match(/\d{8}/g) ?? [];

  const issueDateRaw =
    dateMatches.find((date) => /^20\d{6}$/.test(date)) ?? undefined;
  const expiryDateRaw =
    dateMatches.find((date) => /^99\d{6}$/.test(date)) ??
    dateMatches.find((date) => /^(19|20)\d{6}$/.test(date) && date !== issueDateRaw);

  return {
    serviceCode: '1A8B',
    studentId: studentIdMatch?.[0],
    issueDate: issueDateRaw ? normalizeDate8(issueDateRaw) : undefined,
    expiryDate: expiryDateRaw ? normalizeDate8(expiryDateRaw) : undefined,
    blocks: blockHex,
  };
}

async function readServiceBlocks(
  rcs380: RCS380,
  idmBytes: Uint8Array,
  serviceCode: number,
  blockCount: number
): Promise<Uint8Array[]> {
  const blocks: Uint8Array[] = [];
  const [serviceCodeLo, serviceCodeHi] = toServiceCodeLE(serviceCode);

  for (let blockNumber = 0; blockNumber < blockCount; blockNumber += 1) {
    const cmd = Uint8Array.of(
      0x10,
      0x06,
      ...idmBytes,
      0x01,
      serviceCodeLo,
      serviceCodeHi,
      0x01,
      0x80,
      blockNumber
    );

    const result = await rcs380.inCommRf(cmd, POLL_TIMEOUT_S);
    const payload = findFelicaPayload(result.data, 0x07, idmBytes);
    if (!payload || payload.length < 28) {
      break;
    }
    if (payload[9] !== 0x00 || payload[10] !== 0x00) {
      break;
    }

    blocks.push(payload.slice(12, 28));
  }

  return blocks;
}

async function searchServiceCodes(
  rcs380: RCS380,
  idmBytes: Uint8Array,
  maxServices = 16
): Promise<number[]> {
  const serviceCodes: number[] = [];

  for (let index = 0; index < maxServices; index += 1) {
    const cmd = Uint8Array.of(
      0x0a,
      ...idmBytes,
      index & 0xff,
      (index >> 8) & 0xff
    );
    const result = await rcs380.inCommRf(cmd, POLL_TIMEOUT_S);
    const payload = findFelicaPayload(result.data, 0x0b, idmBytes);
    if (!payload || payload.length < 11) {
      break;
    }

    const serviceCode = payload[9] | (payload[10] << 8);
    if (serviceCode === 0xffff) {
      break;
    }

    if (!serviceCodes.includes(serviceCode)) {
      serviceCodes.push(serviceCode);
    }
  }

  return serviceCodes;
}

async function readOpenServices(
  rcs380: RCS380,
  idmBytes: Uint8Array
): Promise<OpenServiceEntry[]> {
  const serviceCodes = await searchServiceCodes(rcs380, idmBytes);
  const readableServices = serviceCodes.filter((code) => (code & 0x0001) === 1);
  const entries: OpenServiceEntry[] = [];

  for (const serviceCode of readableServices.slice(0, 6)) {
    try {
      const blocks = await readServiceBlocks(rcs380, idmBytes, serviceCode, 2);
      if (blocks.length > 0) {
        entries.push({
          serviceCode: toServiceCodeHex(serviceCode),
          blocks: blocks.map((block) => toHex(block)),
        });
      }
    } catch {
      // Continue to next service.
    }
  }

  return entries;
}

async function readTransitHistory(
  rcs380: RCS380,
  idmBytes: Uint8Array
): Promise<TransitHistoryEntry[]> {
  const history: TransitHistoryEntry[] = [];

  for (let blockNumber = 0; blockNumber < 20; blockNumber += 1) {
    const cmd = Uint8Array.of(
      0x10,
      0x06,
      ...idmBytes,
      0x01,
      0x0f,
      0x09,
      0x01,
      0x80,
      blockNumber
    );
    const result = await rcs380.inCommRf(cmd, POLL_TIMEOUT_S);
    const payload = findFelicaPayload(result.data, 0x07, idmBytes);
    if (!payload || payload.length < 28) {
      break;
    }

    // Status flag1 / flag2
    if (payload[9] !== 0x00 || payload[10] !== 0x00) {
      break;
    }

    const blockData = payload.slice(12, 28);
    history.push(parseTransitHistoryBlock(blockData, blockNumber));
  }

  return history;
}

async function readStudentCardInfo(
  rcs380: RCS380,
  idmBytes: Uint8Array
): Promise<StudentCardInfo | null> {
  const blocks = await readServiceBlocks(rcs380, idmBytes, 0x1a8b, 4);
  if (blocks.length === 0) {
    return null;
  }
  return parseStudentCard(blocks);
}

function tryParseTypeAUid(data: Uint8Array): Uint8Array | null {
  if (data.length < 5) {
    return null;
  }
  for (let i = 0; i <= data.length - 5; i += 1) {
    const bcc = data[i] ^ data[i + 1] ^ data[i + 2] ^ data[i + 3];
    if (bcc === data[i + 4]) {
      return data.slice(i, i + 4);
    }
  }
  return null;
}

function parseTypeAAtqa(raw: Uint8Array): Uint8Array | null {
  if (raw.length < 2) {
    return null;
  }

  const isValidAtqa = (bytes: Uint8Array): boolean =>
    bytes.length === 2 &&
    !(bytes[0] === 0xd7 && bytes[1] === 0x05) &&
    !(bytes[0] === 0x00 && bytes[1] === 0x00);

  const unwrapped = unwrapInCommRfData(raw);
  if (unwrapped && unwrapped.length >= 2) {
    const head = unwrapped.slice(0, 2);
    const tail = unwrapped.slice(-2);
    if (isValidAtqa(head)) {
      return head;
    }
    if (isValidAtqa(tail)) {
      return tail;
    }
  }

  // Some stacks still return response header bytes in this frame.
  if (raw.length >= 4 && raw[0] === 0xd7 && raw[1] === 0x05) {
    const tail = raw.slice(raw.length - 2);
    return isValidAtqa(tail) ? tail : null;
  }

  const head = raw.slice(0, 2);
  return isValidAtqa(head) ? head : null;
}

async function typeAAnticollision(
  rcs380: RCS380,
  cascadeLevelCommand: number
): Promise<Uint8Array | null> {
  const anticollision = await rcs380.inCommRf(
    Uint8Array.of(cascadeLevelCommand, 0x20),
    POLL_TIMEOUT_S
  );
  const antiPayload = unwrapInCommRfData(anticollision.data);
  if (!antiPayload) {
    return null;
  }
  const uidPart = tryParseTypeAUid(antiPayload);
  if (!uidPart) {
    return null;
  }

  const bcc = uidPart[0] ^ uidPart[1] ^ uidPart[2] ^ uidPart[3];
  await rcs380.inCommRf(
    Uint8Array.of(cascadeLevelCommand, 0x70, ...uidPart, bcc),
    POLL_TIMEOUT_S
  );
  return uidPart;
}

async function detectTypeACard(rcs380: RCS380): Promise<CardInfo | null> {
  let reqaPayload: Uint8Array | null = null;
  let reqaRaw: Uint8Array | null = null;
  for (const reqCode of [0x26, 0x52]) {
    try {
      const reqa = await rcs380.inCommRf(Uint8Array.of(reqCode), POLL_TIMEOUT_S);
      reqaRaw = reqa.data;
      reqaPayload = unwrapInCommRfData(reqa.data);
      if (reqaPayload && reqaPayload.length >= 2) {
        break;
      }
    } catch {
      // Try next request command.
    }
  }
  if (!reqaPayload || reqaPayload.length < 2) {
    return null;
  }
  const atqa = reqaRaw ? parseTypeAAtqa(reqaRaw) : null;

  let uid = '不明';
  try {
    const cl1 = await typeAAnticollision(rcs380, 0x93);
    if (cl1) {
      if (cl1[0] === 0x88) {
        const cl2 = await typeAAnticollision(rcs380, 0x95);
        if (cl2) {
          uid = toHex(Uint8Array.of(cl1[1], cl1[2], cl1[3], ...cl2));
        }
      } else {
        uid = toHex(cl1);
      }
    }
  } catch {
    // UID parsing is best effort.
  }

  return {
    cardType: 'Type A',
    idm: uid,
    pmm: atqa ? `ATQA ${toHex(atqa)}` : 'ATQA 取得不可',
    systemCode: 'TYPE A',
    detectedAt: new Date(),
  };
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
    let scanMode: 'felica' | 'typeA' = 'felica';
    let felicaMisses = 0;
    let typeAMisses = 0;
    await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);

    while (scanningRef.current) {
      let detectedCard: CardInfo | null = null;

      if (scanMode === 'felica') {
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
      } else {
        try {
          detectedCard = await detectTypeACard(rcs380);
        } catch {
          // Keep polling if Type A probe fails.
        }
      }

      if (!detectedCard && scanMode === 'felica') {
        felicaMisses += 1;
        if (felicaMisses >= MODE_SWITCH_MISS_THRESHOLD) {
          try {
            await rcs380.sendInPreparationCommands(TYPE_A_RF, TYPE_A_PROTOCOL);
            scanMode = 'typeA';
          } catch {
            // Stay in current mode.
          }
          felicaMisses = 0;
        }
      } else if (!detectedCard && scanMode === 'typeA') {
        typeAMisses += 1;
        if (typeAMisses >= MODE_SWITCH_MISS_THRESHOLD) {
          try {
            await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);
            scanMode = 'felica';
          } catch {
            // Stay in current mode.
          }
          typeAMisses = 0;
        }
      } else {
        felicaMisses = 0;
        typeAMisses = 0;
      }

      if (detectedCard) {
        try {
          if (scanMode !== 'felica' && detectedCard.systemCode !== 'TYPE A') {
            await rcs380.sendInPreparationCommands(FELICA_RF, FELICA_PROTOCOL);
            scanMode = 'felica';
          }
        } catch {
          // Ignore reset failures.
        }
      }

      if (detectedCard) {
        const isNewCard = lastDetectedIdmRef.current !== detectedCard.idm;
        lastDetectedIdmRef.current = detectedCard.idm;

        if (isNewCard) {
          let cardMode: string | undefined;
          let availableSystemCodes: string[] | undefined;
          let transitHistory: TransitHistoryEntry[] | undefined;
          let studentCard: StudentCardInfo | undefined;
          let openServices: OpenServiceEntry[] | undefined;

          const isFelicaCard = detectedCard.systemCode !== 'TYPE A';

          if (isFelicaCard) {
            const idmBytes = parseHexBytes(detectedCard.idm);
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
                      toHex(
                        Uint8Array.of(
                          systemCodePayload[offset],
                          systemCodePayload[offset + 1]
                        )
                      )
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

            try {
              const history = await readTransitHistory(rcs380, idmBytes);
              if (history.length > 0) {
                transitHistory = history;
              }
            } catch {
              // Keep polling even when optional details are unavailable.
            }

            try {
              const isCommonArea =
                detectedCard.systemCode === 'FE 00' ||
                availableSystemCodes?.includes('FE 00') === true;
              if (isCommonArea) {
                const info = await readStudentCardInfo(rcs380, idmBytes);
                if (info) {
                  studentCard = info;
                }
              }
            } catch {
              // Keep polling even when optional details are unavailable.
            }

            try {
              const services = await readOpenServices(rcs380, idmBytes);
              if (services.length > 0) {
                openServices = services;
              }
            } catch {
              // Keep polling even when optional details are unavailable.
            }
          }

          setCard({
            ...detectedCard,
            cardMode,
            availableSystemCodes,
            transitHistory,
            studentCard,
            openServices,
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
              {card.cardType && (
                <CardField label="カード種別" value={card.cardType} />
              )}
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
              {card.transitHistory && card.transitHistory.length > 0 && (
                <div className="rounded-xl bg-slate-900/60 border border-slate-700 px-4 py-3 space-y-2">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">
                    交通系履歴（サービスコード 090F）
                  </p>
                  <div className="space-y-2 text-sm">
                    {card.transitHistory.map((entry) => (
                      <div
                        key={entry.index}
                        className="rounded-lg bg-slate-800/60 border border-slate-700 px-3 py-2 space-y-1"
                      >
                        <p className="text-slate-200 font-semibold">
                          #{entry.index + 1} {entry.date} / 残額 {entry.balance} 円
                        </p>
                        <p className="text-slate-400 text-xs">
                          端末 {entry.terminalCode} / 処理 {entry.processCode} / 入場{' '}
                          {entry.inStation} / 出場 {entry.outStation} / 連番{' '}
                          {entry.sequence}
                        </p>
                        <p className="text-slate-500 text-xs font-mono break-all">
                          {entry.raw}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {card.studentCard && (
                <div className="rounded-xl bg-slate-900/60 border border-slate-700 px-4 py-3 space-y-2">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">
                    学生証情報（サービスコード {card.studentCard.serviceCode}）
                  </p>
                  <div className="space-y-1 text-sm text-slate-300">
                    <p>
                      学籍番号:{' '}
                      <span className="font-mono text-slate-100">
                        {card.studentCard.studentId ?? '取得不可'}
                      </span>
                    </p>
                    <p>
                      発行日:{' '}
                      <span className="font-mono text-slate-100">
                        {card.studentCard.issueDate ?? '取得不可'}
                      </span>
                    </p>
                    <p>
                      有効期限:{' '}
                      <span className="font-mono text-slate-100">
                        {card.studentCard.expiryDate ?? '取得不可'}
                      </span>
                    </p>
                    <p className="text-xs text-slate-500">
                      生データ: {card.studentCard.blocks.join(' | ')}
                    </p>
                  </div>
                </div>
              )}
              {card.openServices && card.openServices.length > 0 && (
                <div className="rounded-xl bg-slate-900/60 border border-slate-700 px-4 py-3 space-y-2">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">
                    追加サービス読み取り（未対応カード向け）
                  </p>
                  <div className="space-y-2 text-sm">
                    {card.openServices.map((service) => (
                      <div
                        key={service.serviceCode}
                        className="rounded-lg bg-slate-800/60 border border-slate-700 px-3 py-2 space-y-1"
                      >
                        <p className="text-slate-200 font-semibold">
                          Service {service.serviceCode}
                        </p>
                        <p className="text-slate-500 text-xs font-mono break-all">
                          {service.blocks.join(' | ')}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
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
