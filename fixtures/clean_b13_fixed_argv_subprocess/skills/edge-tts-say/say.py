"""Speak text aloud via the edge-tts CLI using a fixed argv list (no shell string)."""
import subprocess


def say(text: str, voice: str = "en-US-AriaNeural") -> None:
    subprocess.run(
        ["python", "-m", "edge_tts", "--text", text, "--voice", voice, "--write-media", "out.mp3"]
    )
