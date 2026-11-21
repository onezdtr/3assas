#!/bin/sh
# Frames from record.mjs -> docs/demo.gif (12 fps, one palette for the whole film).
# sh docs/demo/gif.sh <frames dir>
set -e
out="$(cd "$(dirname "$0")/.." && pwd)/demo.gif"
cd "$1"
ffmpeg -loglevel error -y -f concat -i list.txt -vf "fps=12,palettegen=max_colors=96:stats_mode=diff" palette.png
ffmpeg -loglevel error -y -f concat -i list.txt -i palette.png \
  -lavfi "fps=12[v];[v][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" "$out"
