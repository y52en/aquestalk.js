# AquesTalk.js

AquesTalkをWebAssembly(v86)環境で動かし、ブラウザから簡単に利用できるようにしたライブラリです。

DEMO : [https://y52en.github.io/aquestalk.js](https://y52en.github.io/aquestalk.js)

## 特徴
- ブラウザ上でAquesTalk(Win32版)をエミュレートして音声合成
- 複数の音声(f1, f2等)に対応
- npm/TypeScript対応

## インストール

```bash
npm install aquestalk.js
```

## 使い方

このライブラリは、AquesTalkのWin32版DLLを含むzipファイルを別途必要とします。

### 準備
1. [アクエスト社のサイト](https://www.a-quest.com/products/aquestalk.html)からAquesTalkのWin32版をダウンロードします。
2. ダウンロードしたzipファイル（例: `aqtk1-win-101.zip`）を用意します。

### コード例

```typescript
import { load } from 'aquestalk.js';

async function main() {
  // 音声名（f1, f2, m1等）を指定して初期化
  // Vite等のモダンな環境ではアセット(zip/wasm)が自動的に解決されます
  const aq = await load('f1');

  // 音声の生成 (Wave形式のUint8Arrayが返ります)
  const wav = aq.run('ゆっくりしていってね', 100);

  // 再生例 (ブラウザ環境)
  const blob = new Blob([wav], { type: 'audio/wav' });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  audio.play();

  // 使い終わったら破棄
  await aq.destroy();
}

main();
```

## API

### `load(voice: Voice, options?: Options): Promise<AquesTalk>`

音声名（f1, f2, m1, m2, dvd, imd1, jgr, r1）を指定して初期化します。
モダンなバンドラ（Vite, Webpack 5等）を使用している場合、追加設定なしでアセットがロードされます。

- `voice`: 音声名。 `"f1" | "f2" | "m1" | "m2" | "dvd" | "imd1" | "jgr" | "r1"`
- `options`:
    - `baseUrl`: アセット(zip, wasm)のベースURLを手動指定する場合に使用
    - `wasmPath`: `v86.wasm` へのパスを個別に指定する場合に使用

### `loadAquesTalk(zippath: string, dllpath: string, options?: Options): Promise<AquesTalk>`

AquesTalkを初期化します。

- `zippath`: AquesTalkのzipファイルへのパス（URL）
- `dllpath`: zip内のDLLファイルへの相対パス
- `options`:
    - `wasmPath`: `v86.wasm` へのパス。デフォルトは `./v86.wasm`

### `AquesTalk` クラス

#### `run(koe: string, speed?: number): Uint8Array`

音声合成を実行し、WAV形式のデータを返します。

- `koe`: 音声合成する文字列（AquesTalk記法）
- `speed`: 再生速度（デフォルト 100）

#### `destroy(): Promise<void>`

エミュレータを停止し、リソースを解放します。

## ライセンス

### aquesTalk.js (このリポジトリのコード)
[MIT License](LICENSE)

### AquesTalk (エンジンの著作権)
AquesTalkの著作権は株式会社アクエストに帰属します。
利用にあたっては[アクエスト社のライセンス規定](https://www.a-quest.com/licence.html)に従ってください。
詳細なライセンス情報は、配布時のzip内に含まれる `AqLicence.txt` を参照してください。

## よくある質問

- **なぜzipファイルでAquesTalkを読み込んでいるの？**
  `AqLicence.txt` によれば、DLLファイル単体での再配布は禁止されています。これを遵守しつつ利便性を確保するため、ライセンス文書を含むzipファイル形式で扱う構成をとっています。

---

## 参考
- [AquesTalk 開発者ガイド (Linux版)](https://www.a-quest.com/archive/manual/prog_guide_linux.pdf)