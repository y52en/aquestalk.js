import { useState, useEffect } from "react";
import "./App.css";
import { AquesTalk, loadAquesTalk } from "../../src/index.js";

function play_wav(wav: Uint8Array) {
  const blob = new Blob([wav], { type: "audio/wav" });
  const url = URL.createObjectURL(blob);
  const audio = new Audio(url);
  audio.play();
}

function App() {
  const [talkText, setTalkText] = useState("こんにちわ、せかい");
  const [talkEngine, setTalkEngine] = useState<AquesTalk | null>(null);
  useEffect(() => {
    (async () => {
      setTalkEngine(await loadAquesTalk("./f1.zip", "f1/AquesTalk.dll"))
    })();
  }, []);

  return (
    <>
      {/* <Suspense fallback={<div>Loading...</div>}> */}
      <div className="card">
        <button
          onClick={async() =>
          {
            console.time("talkEngine.run");
            talkEngine
              ? play_wav(await talkEngine.run(talkText))
              : console.error("talkEngine is null")
            console.timeEnd("talkEngine.run");
          }
          }
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
      {/* </Suspense> */}
    </>
  );
}

export default App;
