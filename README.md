# AquesTalk.js

![thumbnail](./image.png)

AquesTalkをWebAssembly(v86)環境で動かし、ブラウザやNode.jsで簡単に利用できるようにしたライブラリです。

DEMO : [https://y52en.github.io/aquestalk.js](https://y52en.github.io/aquestalk.js)

## 特徴
- ブラウザ上でAquesTalk(Win32版)をエミュレートして音声合成
- 複数の音声(f1, f2, m1, m2, dvd, imd1, jgr, r1)に対応
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


> ■複製・再配布<br>
> ユーザーは、本ソフトウェアのパッケージを個人利用、商用利用を問わず複製、再配布<br>
> することができます。<br>
> 「ＤＬＬの再配布」の規定を除き、当社から配布されたものと異なるパッケージや部分<br>
> 的な配布はできません。<br>
> <br>
> ■ＤＬＬの再配布<br>
> ユーザーは、次のすべての条件を満たす場合に限り、ＤＬＬを他のプログラム(以下、二<br>
> 次的ソフトウェア）に組み込んで配布することができます。なお、ＤＬＬファイル単体<br>
> での再配布は許諾されておりません。<br>
> <br>
> -本使用許諾契約書ファイルの複製がＤＬＬと同じディレクトリに常に保存されているこ<br>
> と<br>
> <br>
> -ＤＬＬの著作権が当社に帰属することを、その二次的ソフトウェアのユーザーがわかる<br>
> ように明記すること<br>
> <br>
> -本ソフトウェアを使用していることを、その二次的ソフトウェアの利用者がわかるよう<br>
> に明記すること<br>


---

## 参考
- [AquesTalk 開発者ガイド (Linux版)](https://www.a-quest.com/archive/manual/prog_guide_linux.pdf)


## クレジット

ゆっくり立ち絵:	https://kumasannosozaiya.studio.site/
