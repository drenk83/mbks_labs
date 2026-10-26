#!/usr/bin/env sh
# Рендер текста в PNG в стиле терминала: заголовок + содержимое.
# Использование: make-shot.sh out.png "Заголовок" файл.txt [ширина]
set -eu

out=$1
title=$2
src=$3
width=${4:-1100}

font=$(fc-match -f '%{file}' 'Noto Sans Mono')
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

magick -size "$((width - 40))x44" xc:'#101418' -font "$font" -pointsize 17 \
  -fill '#88c0d0' -gravity west -annotate +4+0 "$title" "$tmp/title.png"
magick -background '#101418' -fill '#d8dee9' -font "$font" -pointsize 14 \
  -size "$((width - 40))x" -gravity northwest caption:"@$src" "$tmp/body.png"
magick "$tmp/title.png" "$tmp/body.png" -background '#101418' \
  -gravity northwest -append -bordercolor '#101418' -border 20 "$out"
