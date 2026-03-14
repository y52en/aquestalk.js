import { useState, useEffect } from "react";
import "./App.css";
import { AquesTalk, load, Voice } from "aquestalk.js";

async function play_wav(wav: Uint8Array) {
  const blob = new Blob([wav as any], { type: "audio/wav" });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  await audio.play();
  URL.revokeObjectURL(url);
}

const VOICES: { id: Voice; label: string }[] = [
  { id: "f1", label: "女声1 (f1)" },
  { id: "f2", label: "女声2 (f2)" },
  { id: "imd1", label: "中性 (imd1)" },
  { id: "jgr", label: "機械音 (jgr)" },
  { id: "m1", label: "男声1 (m1)" },
  { id: "m2", label: "男声2 (m2)" },
  { id: "r1", label: "ロボット (r1)" },
  { id: "dvd", label: "ディスカウント (dvd)" },
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
        engine = await load(selectedVoice.id, {
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
          <label htmlFor="voice-select" style={{ marginRight: "0.5rem" }}>
            Voice:
          </label>
          <select
            id="voice-select"
            value={selectedVoice.id}
            onChange={(e) => {
              const voice = VOICES.find((v) => v.id === e.target.value);
              if (voice) setSelectedVoice(voice);
            }}
            disabled={isLoading}
          >
            {VOICES.map((v) => (
              <option key={v.id} value={v.id}>
                {v.label}
              </option>
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
