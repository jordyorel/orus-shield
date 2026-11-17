import { describe, expect, it } from "vitest";
import { encodeQR, qrPath, type QrMatrix } from "./qr";

// Decoding was checked against an independent reader (macOS Vision) for
// versions 1 to 16; these tests pin the structure a reader relies on.

const OTPAUTH =
  "otpauth://totp/Orus%20Shield:jordy%2Bessai1@gmail.com?algorithm=SHA1&digits=6&issuer=Orus%20Shield&period=30&secret=2N72MPVIUIADZTAL46RZJOLASC2CFP37";

const version = (m: QrMatrix) => (m.length - 17) / 4;

/** formatBits reads the 15 format bits around the top-left finder. */
function formatBits(m: QrMatrix): number {
  const cells: [number, number][] = [];
  for (let i = 0; i <= 5; i++) cells.push([8, i]);
  cells.push([8, 7], [8, 8], [7, 8]);
  for (let i = 9; i < 15; i++) cells.push([14 - i, 8]);
  return cells.reduce((acc, [x, y], i) => acc | ((m[y]![x] ? 1 : 0) << i), 0);
}

/** formatBitsCopy reads the second copy (top-right and bottom-left). */
function formatBitsCopy(m: QrMatrix): number {
  const s = m.length;
  let bits = 0;
  for (let i = 0; i < 8; i++) bits |= (m[8]![s - 1 - i] ? 1 : 0) << i;
  for (let i = 8; i < 15; i++) bits |= (m[s - 15 + i]![8] ? 1 : 0) << i;
  return bits;
}

function finderAt(m: QrMatrix, x0: number, y0: number): boolean {
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const ring = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      if (m[y0 + dy]![x0 + dx] !== (ring !== 2)) return false;
    }
  }
  return true;
}

describe("encodeQR", () => {
  it.each([
    ["A", 1],
    ["x".repeat(60), 4],
    [OTPAUTH, 8],
    ["z".repeat(400), 15], // level M holds 412 bytes at version 15
  ])("picks the smallest version for %#", (text, want) => {
    expect(version(encodeQR(text))).toBe(want);
  });

  it.each([["A"], [OTPAUTH], ["z".repeat(400)]])("draws the patterns a reader looks for (%#)", (text) => {
    const m = encodeQR(text);
    const s = m.length;
    expect(m.every((row) => row.length === s)).toBe(true);
    expect(finderAt(m, 0, 0) && finderAt(m, s - 7, 0) && finderAt(m, 0, s - 7)).toBe(true);
    for (let i = 8; i < s - 8; i++) {
      expect(m[6]![i]).toBe(i % 2 === 0); // timing patterns
      expect(m[i]![6]).toBe(i % 2 === 0);
    }
    expect(m[s - 8]![8]).toBe(true); // the dark module
    // Format: level M, a mask from 0 to 7, the same in both copies, and a
    // valid BCH code.
    const f = formatBits(m);
    expect(formatBitsCopy(m)).toBe(f);
    const data = (f ^ 0x5412) >>> 10;
    expect(data >>> 3).toBe(0b00);
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    expect(((data << 10) | rem) ^ 0x5412).toBe(f);
  });

  it("writes the version information from version 7", () => {
    const m = encodeQR("z".repeat(400)); // version 15
    const s = m.length;
    let bits = 0;
    for (let i = 0; i < 18; i++) bits |= (m[Math.floor(i / 3)]![s - 11 + (i % 3)] ? 1 : 0) << i;
    expect(bits >>> 12).toBe(15);
  });

  it("is deterministic", () => {
    expect(encodeQR(OTPAUTH)).toEqual(encodeQR(OTPAUTH));
  });

  it("refuses a text beyond version 40", () => {
    expect(() => encodeQR("z".repeat(3000))).toThrow();
  });
});

describe("qrPath", () => {
  it("draws one square per dark module, offset by the margin", () => {
    expect(qrPath([[true, false], [false, true]], 4)).toBe("M4 4h1v1h-1zM5 5h1v1h-1z");
  });
});
