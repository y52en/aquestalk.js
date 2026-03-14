# AquesTalk.js

AquesTalkをWebAssembly(v86)環境で動かし、ブラウザから簡単に利用できるようにしたライブラリです。

DEMO : [https://y52en.github.io/aquestalk.js](https://y52en.github.io/aquestalk.js)

## 特徴
- ブラウザ上でAquesTalk(Win32版)をエミュレートして音声合成
- 複数の音声(f1, f2等)に対応
- npm/TypeScript対応

## ライセンス

### aquesTalk.js (このリポジトリのコード)
[MIT License](file:///home/y52en/code/aquestalk.js/LICENSE)

### AquesTalk (エンジンの著作権)
AquesTalkの著作権は株式会社アクエストに帰属します。
利用にあたっては[アクエスト社のライセンス規定](https://www.a-quest.com/licence.html)に従ってください。
詳細なライセンス情報は、配布時のzip内に含まれる `AqLicence.txt` を参照してください。

## よくある質問

- **なぜzipファイルでAquesTalkを読み込んでいるの？**
  `AqLicence.txt` によれば、DLLファイル単体での再配布は禁止されています。これを遵守しつつ利便性を確保するため、ライセンス文書を含むzipファイル形式で扱う構成をとっています。

---

## 開発状況 (TODO)
- [ ] 詳しい使い方のドキュメント作成
- [ ] リファクタリング
- [ ] エラーハンドリングの強化

## 参考
- [AquesTalk 開発者ガイド (Linux版)](https://www.a-quest.com/archive/manual/prog_guide_linux.pdf)