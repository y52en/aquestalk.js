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