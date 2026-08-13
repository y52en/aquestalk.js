# AquesTalk.js

![thumbnail](./image.png)

AquesTalkをWebAssembly(v86)環境で動かし、ブラウザやNode.jsで簡単に利用できるようにしたライブラリです。

DEMO : [https://aquestalk-js.y52.dev](https://aquestalk-js.y52.dev)

## 特徴
- ブラウザ上でAquesTalk(Win32版)をエミュレートして音声合成
- 複数の音声(f1, f2, m1, m2, dvd, imd1, jgr, r1)に対応
- TypeScript対応
- [AqKanji2Koe-OpenJTalk-WASM](https://github.com/y52en/AqKanji2Koe-OpenJTalk-WASM) / [`kanji2koe-openjtalk`](https://www.npmjs.com/package/kanji2koe-openjtalk) と組み合わせることで、漢字かな交じり文から読み上げ可能

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

### 漢字かな交じり文を読み上げる

`aquestalk.js` の `run()` は AquesTalk 音声記号列を入力に取ります。
通常の日本語文をそのまま読み上げたい場合は、`kanji2koe-openjtalk` で漢字かな交じり文を音声記号列に変換してから `aquestalk.js` に渡します。

```bash
npm install aquestalk.js kanji2koe-openjtalk
```

```typescript
import { load as loadAquesTalk } from 'aquestalk.js';
import { load as loadKanji2Koe } from 'kanji2koe-openjtalk';

async function main() {
  const kanji2koe = await loadKanji2Koe();
  const aq = await loadAquesTalk('f1');

  const koe = kanji2koe.convert('今日は良い天気ですね。');
  const wav = aq.run(koe, 100);

  // 再生例 (ブラウザ環境)
  const bytes = new ArrayBuffer(wav.byteLength);
  new Uint8Array(bytes).set(wav);
  const blob = new Blob([bytes], { type: 'audio/wav' });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  await audio.play();
  URL.revokeObjectURL(url);

  await aq.destroy();
}

main();
```

関連:
- GitHub: [AqKanji2Koe-OpenJTalk-WASM](https://github.com/y52en/AqKanji2Koe-OpenJTalk-WASM)
- npm: [`kanji2koe-openjtalk`](https://www.npmjs.com/package/kanji2koe-openjtalk)

## API

### `load(voice: Voice, options?: Options): Promise<AquesTalk>`

指定した音声（同梱アセット）を使用して初期化します。

- `voice`: 音声名。以下のいずれかを指定します。
  `"f1" | "f2" | "m1" | "m2" | "dvd" | "imd1" | "jgr" | "r1"`
- `options`:
    - `baseUrl`: アセット(zip, wasm)のベースURLを個別に指定する場合に使用
    - `wasmPath`: `v86.wasm` へのパスを個別に指定する場合に使用（デフォルトは自動解決）
    - `memorySize`: エミュレータに割り当てる物理メモリ（bytes）。省略時はPEイメージ、ヒープ、スタックが収まる最小サイズを自動計算
    - `heapSize`: 合成用ヒープ（bytes、デフォルトは32 MiB）。同梱DLLが受理する最大長の音声記号列を最遅の`speed: 50`で合成できるサイズ

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

入力は分割・省略せず、Shift-JISへ変換した1つの音声記号列としてDLLへ渡します。同梱DLLでは、正しい音声記号列の総入力上限はNULL終端を除いて4094 bytesです。文字数ではなくShift-JISのbytes数で決まり、1フレーズ内の読み記号数などにもDLL固有の制限があります。制限を超えた場合はDLLのエラーコードを含む例外を返し、次の`run()`は通常どおり使用できます。

#### `destroy(): Promise<void>`

エミュレータを停止し、使用していたすべてのリソース（メモリ等）を解放します。

## ベンチマーク

同期連続実行を測定する場合:

```bash
npm run benchmark
```

呼び出し間でイベントループへ戻し、v86のJIT確定を許可する場合:

```bash
BENCH_YIELD=1 npm run benchmark
```

ベンチマークは各反復のWAV出力をSHA-256で検証し、実行時間、RSS、外部メモリ、エミュレータI/O量をJSONで出力します。測定方法と比較結果は [`benchmark/README.md`](benchmark/README.md) を参照してください。

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
