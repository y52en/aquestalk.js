# AquesTalk.js

AquesTalkをWebAssembly(v86)環境で動かし、ブラウザやNode.jsで簡単に利用できるようにしたライブラリです。

DEMO : [https://y52en.github.io/aquestalk.js](https://y52en.github.io/aquestalk.js)

## 特徴
- ブラウザ上でAquesTalk(Win32版)をエミュレートして音声合成
- 複数の音声(f1, f2, m1, m2, dvd, imd1, jgr, r1)を標準同梱
- TypeScript対応

## インストール

```bash
npm install aquestalk.js
```

## 使い方

### 基本的な例

```typescript
import { load } from 'aquestalk.js';

async function main() {
  // 音声名（f1, f2, m1等）を指定して初期化
  // 同梱されているアセットが自動的にロードされます
  const aq = await load('f1');

  // 音声の生成 (Wave形式のUint8Arrayが返ります)
  const wav = aq.run('ゆっくりしていってね', 100);

  // 再生例 (ブラウザ環境)
  const blob = new Blob([wav], { type: 'audio/wav' });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  audio.play();

  // 使い終わったら破棄（エミュレータのリソースを解放）
  await aq.destroy();
}

main();
```

## API

### `load(voice: Voice, options?: Options): Promise<AquesTalk>`

指定した音声（同梱アセット）を使用して初期化します。

- `voice`: 音声名。以下のいずれかを指定します。
  `"f1" | "f2" | "m1" | "m2" | "dvd" | "imd1" | "jgr" | "r1"`
- `options`:
    - `baseUrl`: アセット(zip, wasm)のベースURLを個別に指定する場合に使用
    - `wasmPath`: `v86.wasm` へのパスを個別に指定する場合に使用（デフォルトは自動解決）
    - `memorySize`: エミュレータに割り当てるメモリサイズ（MB）

### `loadAquesTalk(zippath: string, dllpath: string, options?: Options): Promise<AquesTalk>`

独自のzipファイルやDLLを使用して初期化します。

- `zippath`: AquesTalkのzipファイルへのパス（URL）
- `dllpath`: zip内のDLLファイルへの相対パス
- `options`: 上記 `load` と同様

### `AquesTalk` クラス

#### `run(koe: string, speed?: number): Uint8Array`

音声合成を実行し、WAV形式のデータを返します。

- `koe`: 音声合成する文字列（AquesTalk記号表記）
- `speed`: 再生速度（50〜300、デフォルト 100）

#### `destroy(): Promise<void>`

エミュレータを停止し、使用していたすべてのリソース（メモリ等）を解放します。

## ライセンス

### aquestalk.js (このライブラリ)
[MIT License](LICENSE)

### AquesTalk (エンジンの著作権)
AquesTalkの著作権は株式会社アクエストに帰属します。
利用にあたっては[アクエスト社のライセンス規定](https://www.a-quest.com/licence.html)に従ってください。
詳細なライセンス情報は、同梱されている音声zip内の `AqLicence.txt` を参照してください。

ライセンスの規定により、dllファイル単体での再配布は禁止されており、それを回避するためにzipファイルで配布しています。

---

## 参考
- [AquesTalk 開発者ガイド (Linux版)](https://www.a-quest.com/archive/manual/prog_guide_linux.pdf)