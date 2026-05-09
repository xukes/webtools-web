import CryptoJS from 'crypto-js';

export type AesMode = 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR';
export type AesPadding =
  | 'Pkcs7'
  | 'AnsiX923'
  | 'Iso10126'
  | 'Iso97971'
  | 'ZeroPadding'
  | 'NoPadding';
export type OutputEncoding = 'auto' | 'utf8' | 'base64' | 'hex';
export type KeySize = 128 | 192 | 256;

const modeMap = {
  ECB: CryptoJS.mode.ECB,
  CBC: CryptoJS.mode.CBC,
  CFB: CryptoJS.mode.CFB,
  OFB: CryptoJS.mode.OFB,
  CTR: CryptoJS.mode.CTR,
} as const;

const paddingMap = {
  Pkcs7: CryptoJS.pad.Pkcs7,
  AnsiX923: CryptoJS.pad.AnsiX923,
  Iso10126: CryptoJS.pad.Iso10126,
  Iso97971: CryptoJS.pad.Iso97971,
  ZeroPadding: CryptoJS.pad.ZeroPadding,
  NoPadding: CryptoJS.pad.NoPadding,
} as const;

function normalizeKey(key: string, keySize: KeySize) {
  const targetBytes = keySize / 8;
  const parsed = CryptoJS.enc.Utf8.parse(key);
  const words = parsed.words.slice(0, Math.ceil(targetBytes / 4));
  const normalized = CryptoJS.lib.WordArray.create(words, parsed.sigBytes);

  if (normalized.sigBytes < targetBytes) {
    normalized.concat(CryptoJS.lib.WordArray.create([], targetBytes - normalized.sigBytes));
  }

  normalized.sigBytes = targetBytes;
  normalized.clamp();
  return normalized;
}

function normalizeIv(iv: string) {
  if (!iv.trim()) {
    return CryptoJS.lib.WordArray.create([0, 0, 0, 0], 16);
  }

  const hash = CryptoJS.SHA256(iv);
  return CryptoJS.lib.WordArray.create(hash.words.slice(0, 4), 16);
}

function toWordArray(text: string, encoding: OutputEncoding) {
  if (encoding === 'auto') {
    return CryptoJS.enc.Utf8.parse(text);
  }

  if (encoding === 'utf8') {
    return CryptoJS.enc.Utf8.parse(text);
  }

  if (encoding === 'base64') {
    return CryptoJS.enc.Base64.parse(text);
  }

  return CryptoJS.enc.Hex.parse(text);
}

function cipherTextToParams(text: string, encoding: OutputEncoding) {
  const compact = text.replace(/\s+/g, '');

  if (encoding === 'auto') {
    return compact;
  }

  if (encoding === 'utf8') {
    return compact;
  }

  if (encoding === 'hex' && compact.length % 2 !== 0) {
    throw new Error('HEX 密文长度必须是偶数');
  }

  if (encoding === 'base64' && compact.length % 4 === 1) {
    throw new Error('Base64 密文长度不合法，可能被截断或少复制了字符');
  }

  const parsed =
    encoding === 'hex' ? CryptoJS.enc.Hex.parse(compact) : CryptoJS.enc.Base64.parse(compact);

  return CryptoJS.lib.CipherParams.create({
    ciphertext: parsed,
  });
}

function formatWordArray(wordArray: CryptoJS.lib.WordArray, encoding: OutputEncoding) {
  if (encoding === 'auto') {
    return wordArray.toString(CryptoJS.enc.Base64);
  }

  if (encoding === 'utf8') {
    try {
      return wordArray.toString(CryptoJS.enc.Utf8);
    } catch {
      throw new Error('解析失败：解密结果可能不是合法的 UTF-8 文本');
    }
  }

  if (encoding === 'base64') {
    return wordArray.toString(CryptoJS.enc.Base64);
  }

  return wordArray.toString(CryptoJS.enc.Hex);
}

export function detectEncoding(text: string): OutputEncoding {
  const value = text.trim();

  if (!value) {
    return 'utf8';
  }

  if (/^(?:0x)?[0-9a-fA-F]+$/.test(value) && value.replace(/^0x/, '').length % 2 === 0) {
    return 'hex';
  }

  if (/^[A-Za-z0-9+/=\s]+$/.test(value) && value.replace(/\s+/g, '').length % 4 === 0) {
    return 'base64';
  }

  return 'utf8';
}

export function encryptAes(
  text: string,
  options: {
    key: string;
    iv: string;
    mode: AesMode;
    padding: AesPadding;
    keySize: KeySize;
    inputEncoding: OutputEncoding;
    outputEncoding: OutputEncoding;
  },
) {
  const key = normalizeKey(options.key, options.keySize);
  const iv = options.mode === 'ECB' ? undefined : normalizeIv(options.iv);
  const message = toWordArray(text, options.inputEncoding);
  const config = {
    iv,
    mode: modeMap[options.mode],
    padding: paddingMap[options.padding],
  };

  const encrypted = CryptoJS.AES.encrypt(message, key, config);

  return formatWordArray(encrypted.ciphertext, options.outputEncoding);
}

export function decryptAes(
  text: string,
  options: {
    key: string;
    iv: string;
    mode: AesMode;
    padding: AesPadding;
    keySize: KeySize;
    inputEncoding: OutputEncoding;
    outputEncoding: OutputEncoding;
  },
) {
  const key = normalizeKey(options.key, options.keySize);
  const iv = options.mode === 'ECB' ? undefined : normalizeIv(options.iv);
  const cipherText = cipherTextToParams(text, options.inputEncoding);
  const config = {
    iv,
    mode: modeMap[options.mode],
    padding: paddingMap[options.padding],
  };

  const decrypted = CryptoJS.AES.decrypt(cipherText, key, config);

  return formatWordArray(decrypted, options.outputEncoding);
}
