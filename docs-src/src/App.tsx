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

function App() {
  const [talkText, setTalkText] = useState("こんにちわ、せかい");
  const [talkEngine, setTalkEngine] = useState<AquesTalk | null>(null);
  useEffect(() => {
    (async () => {
      setTalkEngine(await loadAquesTalk("./f1.zip", "f1/AquesTalk.dll"));
    })();
  }, []);

  return (
    <>
      <div className="card">
        <button
          onClick={async () => {
            if (talkEngine == null) {
              console.error("talkEngine is null");
              alert("talkEngine is null");
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
          PLAY!
        </button>
      </div>
      <div>
        <textarea
          value={talkText}
          onChange={(e) => setTalkText(e.target.value)}
        />
      </div>
    </>
  );
}

export default App;
