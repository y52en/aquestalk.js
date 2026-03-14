import { useState, useEffect } from "react";
import "./App.css";
import { AquesTalk, loadAquesTalk } from "../../src/index.js";

async function play_wav(wav: Uint8Array) {
  const blob = new Blob([wav], { type: "audio/wav" });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  await audio.play();
  URL.revokeObjectURL(url);
}

const VOICES = [
  { id: "f1", label: "女声1 (f1)", zip: "./f1.zip", dll: "f1/AquesTalk.dll" },
  { id: "f2", label: "女声2 (f2)", zip: "./f2.zip", dll: "f2/AquesTalk.dll" },
  { id: "imd1", label: "中性 (imd1)", zip: "./imd1.zip", dll: "imd1/AquesTalk.dll" },
  { id: "jgr", label: "機械音 (jgr)", zip: "./jgr.zip", dll: "jgr/AquesTalk.dll" },
  { id: "m1", label: "男声1 (m1)", zip: "./m1.zip", dll: "m1/AquesTalk.dll" },
  { id: "m2", label: "男声2 (m2)", zip: "./m2.zip", dll: "m2/AquesTalk.dll" },
  { id: "r1", label: "ロボット (r1)", zip: "./r1.zip", dll: "r1/AquesTalk.dll" },
  { id: "dvd", label: "ディスカウント (dvd)", zip: "./dvd.zip", dll: "dvd/AquesTalk.dll" },
];

function App() {
  const [talkText, setTalkText] = useState("こんにちわ、せかい");
  const [selectedVoice, setSelectedVoice] = useState(VOICES[0]);
  const [talkEngine, setTalkEngine] = useState<AquesTalk | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    let engine: AquesTalk | null = null;
    (async () => {
      setIsLoading(true);
      setTalkEngine(null);
      try {
        engine = await loadAquesTalk(selectedVoice.zip, selectedVoice.dll, {
          memorySize: 1024 * 1024 * 1024, // 1GB
        });
        setTalkEngine(engine);
      } catch (e) {
        console.error(e);
        alert(`Failed to load engine: ${e}`);
      } finally {
        setIsLoading(false);
      }
    })();

    return () => {
      if (engine) {
        engine.destroy();
      }
    };
  }, [selectedVoice]);

  return (
    <>
      <h1>AquesTalk.js Multi-Voice Demo</h1>
      <div className="card">
        <div style={{ marginBottom: "1rem" }}>
          <label htmlFor="voice-select" style={{ marginRight: "0.5rem" }}>Voice:</label>
          <select
            id="voice-select"
            value={selectedVoice.id}
            onChange={(e) => {
              const voice = VOICES.find(v => v.id === e.target.id) || VOICES.find(v => v.id === e.target.value);
              if (voice) setSelectedVoice(voice);
            }}
            disabled={isLoading}
          >
            {VOICES.map(v => (
              <option key={v.id} value={v.id}>{v.label}</option>
            ))}
          </select>
        </div>
        <div style={{ marginBottom: "1rem" }}>
          <textarea
            style={{ width: "100%", height: "100px", padding: "0.5rem" }}
            value={talkText}
            onChange={(e) => setTalkText(e.target.value)}
            placeholder="喋らせたい文字を入力..."
          />
        </div>
        <button
          disabled={talkEngine == null || isLoading}
          onClick={async () => {
            if (talkEngine == null) {
              console.error("talkEngine is null");
              return;
            }
            console.time("talkEngine.run");
            try {
              play_wav(await talkEngine.run(talkText));
            } catch (e) {
              console.error(e);
              alert(e);
            }
            console.timeEnd("talkEngine.run");
          }}
        >
          {isLoading ? "Loading..." : "PLAY!"}
        </button>
      </div>
    </>
  );
}

export default App;
