import { useMemo, useState } from 'react';
import {
  detectEncoding,
  decryptAes,
  encryptAes,
  type AesMode,
  type AesPadding,
  type KeySize,
  type OutputEncoding,
} from './lib/aes';

const modeOptions: AesMode[] = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'];
const paddingOptions: AesPadding[] = [
  'Pkcs7',
  'AnsiX923',
  'Iso10126',
  'Iso97971',
  'ZeroPadding',
  'NoPadding',
];
const keySizes: KeySize[] = [128, 192, 256];
const encodingOptions: Array<{ value: OutputEncoding; label: string }> = [
  { value: 'auto', label: '自动检查' },
  { value: 'utf8', label: 'UTF-8' },
  { value: 'base64', label: 'BASE64' },
  { value: 'hex', label: 'HEX' },
];

function getEncodingLabel(encoding: OutputEncoding) {
  return encodingOptions.find((option) => option.value === encoding)?.label ?? encoding;
}

function formatDisplayText(text: string) {
  try {
    const parsed = JSON.parse(text);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return text;
  }
}

function App() {
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [inputEncoding, setInputEncoding] = useState<OutputEncoding>('utf8');
  const [outputEncoding, setOutputEncoding] = useState<OutputEncoding>('auto');
  const [mode, setMode] = useState<AesMode>('ECB');
  const [padding, setPadding] = useState<AesPadding>('Pkcs7');
  const [keySize, setKeySize] = useState<KeySize>(128);
  const [key, setKey] = useState('');
  const [iv, setIv] = useState('');
  const [status, setStatus] = useState('准备就绪');

  const panelBorder = useMemo(
    () => (mode === 'ECB' ? 'border-emerald-200' : 'border-amber-200'),
    [mode],
  );

  const resolvedOutputEncoding = outputEncoding === 'auto' ? 'utf8' : outputEncoding;

  const handleEncrypt = () => {
    try {
      const result = encryptAes(inputText, {
        key,
        iv,
        mode,
        padding,
        keySize,
        inputEncoding,
        outputEncoding: outputEncoding === 'auto' ? 'base64' : outputEncoding,
      });
      setOutputText(result);
      setStatus('加密完成');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : '加密失败');
    }
  };

  const handleDecrypt = () => {
    try {
      const result = decryptAes(inputText, {
        key,
        iv,
        mode,
        padding,
        keySize,
        inputEncoding: outputEncoding === 'auto' ? detectEncoding(inputText) : inputEncoding,
        outputEncoding: resolvedOutputEncoding,
      });
      setOutputText(formatDisplayText(result));
      setStatus(`解密完成（${getEncodingLabel(resolvedOutputEncoding)}）`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : '解密失败');
    }
  };

  const handleCopy = async () => {
    if (!outputText) {
      setStatus('没有可复制的结果');
      return;
    }

    await navigator.clipboard.writeText(outputText);
    setStatus('结果已复制到剪贴板');
  };

  const handleUrlEncode = () => {
    if (!outputText) {
      setStatus('没有可编码的结果');
      return;
    }

    setOutputText(encodeURIComponent(outputText));
    setStatus('UrlEncode 完成');
  };

  const handleUrlDecode = () => {
    if (!outputText) {
      setStatus('没有可解码的结果');
      return;
    }

    try {
      setOutputText(formatDisplayText(decodeURIComponent(outputText)));
      setStatus('UrlDecode 完成');
    } catch {
      setStatus('UrlDecode 失败：内容不是合法的 URL 编码');
    }
  };

  const handleClear = () => {
    setOutputText('');
    setStatus('输出已清空');
  };

  const handleInputClear = () => {
    setInputText('');
    setStatus('输入已清空');
  };

  return (
    <main className="min-h-screen bg-[linear-gradient(180deg,#f6f7f2_0%,#f9faf5_100%)] p-4 text-slate-700 md:p-6">
      <div className="mx-auto flex h-[calc(100vh-2rem)] max-w-[1600px] flex-col gap-4 lg:h-[calc(100vh-3rem)] lg:flex-row">
        <section className={`panel flex min-h-0 flex-1 flex-col border-2 ${panelBorder} p-3`}>
          <div className="mb-2 flex items-center justify-between gap-2">
            <label className="panel-label mb-0">输入内容</label>
            <button
              type="button"
              className="rounded-md border border-slate-300 px-3 py-1 text-sm"
              onClick={handleInputClear}
            >
              清空
            </button>
          </div>
          <textarea
            className="min-h-0 flex-1 w-full resize-none rounded-md border border-slate-300 bg-white p-4 text-base leading-7 outline-none focus:border-emerald-400 focus:ring-2 focus:ring-emerald-100"
            placeholder="请输入需要加密或解密的内容"
            value={inputText}
            onChange={(event) => setInputText(event.target.value)}
          />
        </section>

        <aside className="w-full lg:h-full lg:w-[320px]">
          <div className="panel flex h-full min-h-0 flex-col border-2 border-emerald-200 p-4">
            <div className="space-y-3">
              <div>
                <label className="panel-label">输入编码</label>
                <select
                  className="field"
                  value={inputEncoding}
                  onChange={(event) => setInputEncoding(event.target.value as OutputEncoding)}
                >
                  {encodingOptions.slice(1).map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="panel-label">输出编码</label>
                <select
                  className="field"
                  value={outputEncoding}
                  onChange={(event) => setOutputEncoding(event.target.value as OutputEncoding)}
                >
                  {encodingOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="panel-label">模式</label>
                <select className="field" value={mode} onChange={(event) => setMode(event.target.value as AesMode)}>
                  {modeOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="panel-label">填充</label>
                <select
                  className="field"
                  value={padding}
                  onChange={(event) => setPadding(event.target.value as AesPadding)}
                >
                  {paddingOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="panel-label">密钥长度</label>
                <select
                  className="field"
                  value={keySize}
                  onChange={(event) => setKeySize(Number(event.target.value) as KeySize)}
                >
                  {keySizes.map((option) => (
                    <option key={option} value={option}>
                      {option} bits
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="panel-label">KEY / 密码</label>
                <input
                  className="field"
                  type="text"
                  placeholder="请输入密码"
                  value={key}
                  onChange={(event) => setKey(event.target.value)}
                />
              </div>

              {mode !== 'ECB' ? (
                <div>
                  <label className="panel-label">IV</label>
                  <input
                    className="field"
                    placeholder="请输入 IV"
                    value={iv}
                    onChange={(event) => setIv(event.target.value)}
                  />
                </div>
              ) : null}

              <div className="space-y-2 pt-2">
                <button
                  type="button"
                  className="btn w-full bg-emerald-500 hover:bg-emerald-600"
                  onClick={handleEncrypt}
                >
                  加密
                </button>
                <button
                  type="button"
                  className="btn w-full bg-amber-400 hover:bg-amber-500"
                  onClick={handleDecrypt}
                >
                  解密
                </button>
                <div className="flex items-center justify-end rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm">
                  <span className="text-xs text-slate-500">{status}</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        <section className="panel flex min-h-0 flex-1 flex-col border-2 border-amber-200 p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <label className="panel-label mb-0">输出结果</label>
            <div className="flex flex-wrap gap-2">
              <button type="button" className="rounded-md border border-slate-300 px-3 py-1 text-sm" onClick={handleCopy}>
                复制
              </button>
              <button type="button" className="rounded-md border border-slate-300 px-3 py-1 text-sm" onClick={handleClear}>
                清空
              </button>
              <button
                type="button"
                className="rounded-md border border-slate-300 px-3 py-1 text-sm"
                onClick={handleUrlDecode}
              >
                UrlDecode 解码
              </button>
              <button
                type="button"
                className="rounded-md border border-slate-300 px-3 py-1 text-sm"
                onClick={handleUrlEncode}
              >
                UrlEncode 编码
              </button>
            </div>
          </div>
          <textarea
            className="min-h-0 flex-1 w-full resize-none rounded-md border border-slate-300 bg-white p-4 text-base leading-7 outline-none focus:border-amber-400 focus:ring-2 focus:ring-amber-100"
            placeholder="加密或解密的内容将会在这里显示"
            value={outputText}
            readOnly
          />
        </section>
      </div>
    </main>
  );
}

export default App;
