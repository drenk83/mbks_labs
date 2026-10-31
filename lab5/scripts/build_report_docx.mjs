#!/usr/bin/env node
// Сборка lab5/mbks_lab_5.docx из lab5/report.md.
// Запуск: node lab5/scripts/build_report_docx.mjs
// Пакет docx берётся из DOCX_PKG или /tmp/lab5/docx-work.

import fs from "fs";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const docxRoot = process.env.DOCX_PKG || "/tmp/lab5/docx-work";
const require = createRequire(path.join(docxRoot, "package.json"));
const {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  HeadingLevel,
  ImageRun,
  LevelFormat,
  Packer,
  PageNumber,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  VerticalAlign,
  WidthType,
} = require("docx");

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mdPath = path.join(root, "report.md");
const outPath = path.join(root, "mbks_lab_5.docx");
const fridaDir = path.join(root, "results", "frida");

const PAGE_W = 11906;
const PAGE_H = 16838;
const MARGIN = 1134;
const CONTENT = PAGE_W - MARGIN * 2;

const FONT = "Times New Roman";
const MONO = "Courier New";
const bodySize = 24;
const line = 276;

function runs(text, extra = {}) {
  const size = extra.size || bodySize;
  const base = { font: extra.font || FONT, size };
  const parts = [];
  const re = /`([^`]+)`|\*\*([^*]+)\*\*/g;
  let last = 0;
  let match;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(new TextRun({ ...base, text: text.slice(last, match.index), bold: extra.bold, italics: extra.italics }));
    }
    if (match[1] !== undefined) {
      parts.push(new TextRun({ text: match[1], font: MONO, size: Math.max(18, size - 2), bold: extra.bold }));
    } else {
      parts.push(new TextRun({ ...base, text: match[2], bold: true, italics: extra.italics }));
    }
    last = match.index + match[0].length;
  }
  if (last < text.length || parts.length === 0) {
    parts.push(new TextRun({ ...base, text: text.slice(last), bold: extra.bold, italics: extra.italics }));
  }
  return parts;
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((cell) => cell.trim());
}

function isSeparator(cells) {
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function parse(markdown) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let i = 0;
  let center = true;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === "") {
      i += 1;
      continue;
    }
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const body = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1;
      blocks.push({ type: "code", lang, lines: body });
      continue;
    }
    if (line.startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        const cells = splitRow(lines[i]);
        if (!isSeparator(cells) && !cells.every((cell) => cell === "")) {
          rows.push(cells);
        }
        i += 1;
      }
      if (rows.length) blocks.push({ type: "table", rows, center });
      continue;
    }
    const heading = /^(#{1,3}) (.+)$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      const text = heading[2].trim();
      if (/^## \d+\./.test(line)) center = false;
      blocks.push({ type: "h", level, text, center });
      i += 1;
      continue;
    }
    if (/^[-*] /.test(line)) {
      const items = [];
      while (i < lines.length && /^[-*] /.test(lines[i])) {
        items.push(lines[i].replace(/^[-*] /, ""));
        i += 1;
      }
      blocks.push({ type: "ul", items });
      continue;
    }
    if (/^\d+\. /.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\. /.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\. /, ""));
        i += 1;
      }
      blocks.push({ type: "ol", items });
      continue;
    }
    const para = [line.trim()];
    i += 1;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].startsWith("#") &&
      !lines[i].startsWith("|") &&
      !lines[i].startsWith("```") &&
      !/^[-*] /.test(lines[i]) &&
      !/^\d+\. /.test(lines[i])
    ) {
      para.push(lines[i].trim());
      i += 1;
    }
    blocks.push({ type: "p", text: para.join(" "), center });
  }
  return blocks;
}

const thin = { style: BorderStyle.SINGLE, size: 4, color: "B0B0B0" };
const borders = { top: thin, bottom: thin, left: thin, right: thin };
const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const noBorders = { top: none, bottom: none, left: none, right: none };

function widths(n) {
  const base = Math.floor(CONTENT / n);
  const out = Array(n).fill(base);
  out[n - 1] = CONTENT - base * (n - 1);
  return out;
}

function cell(text, width, header) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: header ? { fill: "D9E2F3", type: ShadingType.CLEAR } : undefined,
    margins: { top: 60, bottom: 60, left: 80, right: 80 },
    verticalAlign: VerticalAlign.CENTER,
    children: [
      new Paragraph({
        spacing: { line, lineRule: "auto" },
        children: runs(text, { bold: header, size: 20 }),
      }),
    ],
  });
}

function makeTable(rows) {
  const cols = Math.max(...rows.map((row) => row.length));
  const colW = widths(cols);
  const normalized = rows.map((row) => {
    const copy = row.slice();
    while (copy.length < cols) copy.push("");
    return copy;
  });
  return new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: colW,
    rows: normalized.map((row, index) => new TableRow({
      tableHeader: index === 0,
      cantSplit: true,
      children: row.map((text, col) => cell(text, colW[col], index === 0)),
    })),
  });
}

function codeBlock(lines) {
  const text = lines.join("\n");
  return new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: [CONTENT],
    rows: [
      new TableRow({
        cantSplit: true,
        children: [
          new TableCell({
            borders,
            width: { size: CONTENT, type: WidthType.DXA },
            shading: { fill: "F4F4F4", type: ShadingType.CLEAR },
            margins: { top: 80, bottom: 80, left: 120, right: 120 },
            children: text.split("\n").map((lineText) => new Paragraph({
              spacing: { line: 240, lineRule: "auto" },
              children: [new TextRun({ text: lineText.length ? lineText : " ", font: MONO, size: 18 })],
            })),
          }),
        ],
      }),
    ],
  });
}

function phoneImage(fileName, caption) {
  const data = fs.readFileSync(path.join(fridaDir, fileName));
  const width = 230;
  const height = Math.round(width * (2400 / 1080));
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 80, after: 40 },
      children: [
        new ImageRun({
          type: "png",
          data,
          transformation: { width, height },
          altText: { name: caption, description: caption, title: caption },
        }),
      ],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 160 },
      children: runs(caption, { italics: true, size: 20 }),
    }),
  ];
}

function figures() {
  const left = phoneImage("screen-eml.png", "Рисунок 1. Письмо под хуками Frida, маркер LAB5-EML-MARKER");
  const right = phoneImage("screen-scanner.png", "Рисунок 2. Сканер документов после загрузки libcamera360-arcadia.so");
  const half = Math.floor(CONTENT / 2);
  const colW = [half, CONTENT - half];
  return new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: colW,
    rows: [
      new TableRow({
        cantSplit: true,
        children: [left, right].map((children, index) => new TableCell({
          borders: noBorders,
          width: { size: colW[index], type: WidthType.DXA },
          margins: { top: 40, bottom: 40, left: 60, right: 60 },
          children,
        })),
      }),
    ],
  });
}

const markdown = fs.readFileSync(mdPath, "utf8");
const blocks = parse(markdown);
const numbered = blocks.filter((block) => block.type === "ol");

const children = [];
let sawFigures = false;
for (const block of blocks) {
  if (block.type === "h") {
    const heading = block.level === 1 ? HeadingLevel.HEADING_1
      : block.level === 2 ? HeadingLevel.HEADING_2
        : HeadingLevel.HEADING_3;
    children.push(new Paragraph({
      heading,
      alignment: block.center ? AlignmentType.CENTER : AlignmentType.LEFT,
      spacing: { before: block.level === 1 ? 200 : 280, after: 120, line, lineRule: "auto" },
      children: runs(block.text, { bold: true, size: block.level === 1 ? 32 : block.level === 2 ? 28 : 24 }),
    }));
    continue;
  }
  if (block.type === "p") {
    children.push(new Paragraph({
      alignment: block.center ? AlignmentType.CENTER : AlignmentType.JUSTIFIED,
      spacing: { after: 120, line, lineRule: "auto" },
      children: runs(block.text),
    }));
    if (!sawFigures && block.text.includes("screen-scanner.png")) {
      children.push(figures());
      sawFigures = true;
    }
    continue;
  }
  if (block.type === "code") {
    children.push(codeBlock(block.lines));
    children.push(new Paragraph({ spacing: { after: 80 }, children: [] }));
    continue;
  }
  if (block.type === "table") {
    children.push(makeTable(block.rows));
    children.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
    continue;
  }
  if (block.type === "ul") {
    for (const item of block.items) {
      children.push(new Paragraph({
        numbering: { reference: "bullets", level: 0 },
        spacing: { after: 60, line, lineRule: "auto" },
        children: runs(item),
      }));
    }
    continue;
  }
  if (block.type === "ol") {
    const reference = `ol-${numbered.indexOf(block)}`;
    for (const item of block.items) {
      children.push(new Paragraph({
        numbering: { reference, level: 0 },
        spacing: { after: 60, line, lineRule: "auto" },
        children: runs(item),
      }));
    }
  }
}

const numbering = {
  config: [
    {
      reference: "bullets",
      levels: [{
        level: 0,
        format: LevelFormat.BULLET,
        text: "•",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    },
    ...numbered.map((_, index) => ({
      reference: `ol-${index}`,
      levels: [{
        level: 0,
        format: LevelFormat.DECIMAL,
        text: "%1.",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    })),
  ],
};

const doc = new Document({
  creator: "Чупров Е. А.",
  title: "Лабораторная работа № 5. Аудит безопасности мобильных приложений",
  description: "Модели безопасности компьютерных систем, 2026",
  styles: {
    default: {
      document: { run: { font: FONT, size: bodySize } },
    },
    paragraphStyles: [
      {
        id: "Heading1",
        name: "Heading 1",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { font: FONT, size: 32, bold: true },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 0 },
      },
      {
        id: "Heading2",
        name: "Heading 2",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { font: FONT, size: 28, bold: true },
        paragraph: { spacing: { before: 280, after: 120 }, outlineLevel: 1 },
      },
      {
        id: "Heading3",
        name: "Heading 3",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { font: FONT, size: 24, bold: true },
        paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 2 },
      },
    ],
  },
  numbering,
  sections: [{
    properties: {
      page: {
        size: { width: PAGE_W, height: PAGE_H },
        margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
      },
    },
    footers: {
      default: new Footer({
        children: [
          new Paragraph({
            border: { top: { style: BorderStyle.SINGLE, size: 6, color: "B0B0B0", space: 8 } },
            spacing: { before: 80 },
            children: [
              new TextRun({ text: "МБКС, лабораторная работа № 5, Чупров Е. А.    стр. ", font: FONT, size: 18, color: "555555" }),
              new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18, color: "555555" }),
            ],
          }),
        ],
      }),
    },
    children,
  }],
});

const buffer = await Packer.toBuffer(doc);
fs.writeFileSync(outPath, buffer);
console.log(`wrote ${outPath} bytes=${buffer.length} figures=${sawFigures}`);
