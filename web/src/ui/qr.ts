// QR code encoder (ISO/IEC 18004), for the otpauth:// link of the MFA
// enrolment page. Written here rather than added as a dependency: the page
// handles the TOTP secret, and the encoder is small. It supports what that
// link needs: byte mode, error correction level M (15 % of the symbol can be
// damaged), versions 1 to 40, automatic mask choice.
//
// The structure follows the standard: data codewords, Reed-Solomon error
// correction per block, interleaving, then placement in a matrix that holds
// the function patterns (finders, timing, alignment, format and version).

/** QrMatrix is a square of modules: true is dark. Index [y][x]. */
export type QrMatrix = boolean[][];

// Per version (index 1 to 40) at level M: error correction codewords per
// block, and number of blocks (ISO/IEC 18004, table 9).
const ECC_PER_BLOCK = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
const BLOCKS = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37,
  38, 40, 43, 45, 47, 49,
];
const LEVEL_M_FORMAT = 0b00; // format bits of level M

/** encodeQR returns the QR code of text (UTF-8 bytes). */
export function encodeQR(text: string): QrMatrix {
  const bytes = [...new TextEncoder().encode(text)];
  const version = pickVersion(bytes.length);
  const data = dataCodewords(bytes, version);
  const q = new Builder(version);
  q.drawFunctionPatterns();
  q.drawCodewords(withErrorCorrection(data, version));
  let best = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    q.applyMask(mask);
    q.drawFormatBits(mask);
    const score = q.penalty();
    if (score < bestScore) {
      best = mask;
      bestScore = score;
    }
    q.applyMask(mask); // XOR again: undoes it
  }
  q.applyMask(best);
  q.drawFormatBits(best);
  return q.modules;
}

/** rawDataModules counts the modules left for data and error correction. */
function rawDataModules(ver: number): number {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}

function dataCapacity(ver: number): number {
  return Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK[ver]! * BLOCKS[ver]!;
}

function countBits(ver: number): number {
  return ver <= 9 ? 8 : 16; // byte mode character count indicator
}

function pickVersion(n: number): number {
  for (let ver = 1; ver <= 40; ver++) {
    if (4 + countBits(ver) + 8 * n <= dataCapacity(ver) * 8) return ver;
  }
  throw new Error("text too long for a QR code");
}

/** dataCodewords lays out mode, length, data, terminator and padding. */
function dataCodewords(bytes: number[], ver: number): number[] {
  const bits: number[] = [];
  const put = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4); // byte mode
  put(bytes.length, countBits(ver));
  for (const b of bytes) put(b, 8);
  const capacity = dataCapacity(ver) * 8;
  put(0, Math.min(4, capacity - bits.length)); // terminator
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) put(pad, 8);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  return out;
}

/** withErrorCorrection splits data into blocks, adds each block's
 * Reed-Solomon codewords and interleaves the result. */
function withErrorCorrection(data: number[], ver: number): number[] {
  const blocks = BLOCKS[ver]!;
  const eccLen = ECC_PER_BLOCK[ver]!;
  const raw = Math.floor(rawDataModules(ver) / 8);
  const shortBlocks = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks); // data + ecc of a short block
  const divisor = rsDivisor(eccLen);
  const all: number[][] = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < shortBlocks ? 0 : 1));
    k += dat.length;
    const ecc = rsRemainder(dat, divisor);
    if (i < shortBlocks) dat.push(0); // placeholder, skipped below
    all.push(dat.concat(ecc));
  }
  const out: number[] = [];
  for (let i = 0; i < all[0]!.length; i++) {
    all.forEach((block, j) => {
      if (i !== shortLen - eccLen || j >= shortBlocks) out.push(block[i]!);
    });
  }
  return out;
}

/** gfMul multiplies in GF(256) modulo x^8 + x^4 + x^3 + x^2 + 1. */
function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** rsDivisor is the generator polynomial of the given degree. */
function rsDivisor(degree: number): number[] {
  const out = new Array<number>(degree).fill(0);
  out[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < out.length; j++) {
      out[j] = gfMul(out[j]!, root);
      if (j + 1 < out.length) out[j]! ^= out[j + 1]!;
    }
    root = gfMul(root, 0x02);
  }
  return out;
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const out = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ out.shift()!;
    out.push(0);
    divisor.forEach((coef, i) => (out[i]! ^= gfMul(coef, factor)));
  }
  return out;
}

const bit = (x: number, i: number) => ((x >>> i) & 1) !== 0;

class Builder {
  readonly version: number;
  readonly size: number;
  readonly modules: QrMatrix;
  private readonly fixed: boolean[][]; // function patterns, never masked

  constructor(version: number) {
    this.version = version;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.fixed = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  private set(x: number, y: number, dark: boolean) {
    this.modules[y]![x] = dark;
    this.fixed[y]![x] = true;
  }

  drawFunctionPatterns() {
    const s = this.size;
    for (let i = 0; i < s; i++) {
      this.set(6, i, i % 2 === 0); // timing patterns
      this.set(i, 6, i % 2 === 0);
    }
    for (const [x, y] of [[3, 3], [s - 4, 3], [3, s - 4]] as const) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const d = Math.max(Math.abs(dx), Math.abs(dy));
          const xx = x + dx;
          const yy = y + dy;
          if (xx >= 0 && xx < s && yy >= 0 && yy < s) this.set(xx, yy, d !== 2 && d !== 4); // finder + separator
        }
      }
    }
    const pos = this.alignmentPositions();
    const n = pos.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue; // finders
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) this.set(pos[i]! + dx, pos[j]! + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    this.drawFormatBits(0); // reserves the area; drawn for real after masking
    if (this.version >= 7) {
      let rem = this.version;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      const bits = (this.version << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const a = s - 11 + (i % 3);
        const b = Math.floor(i / 3);
        this.set(a, b, bit(bits, i));
        this.set(b, a, bit(bits, i));
      }
    }
  }

  private alignmentPositions(): number[] {
    if (this.version === 1) return [];
    const n = Math.floor(this.version / 7) + 2;
    const step = this.version === 32 ? 26 : Math.ceil((this.size - 13) / (n * 2 - 2)) * 2;
    const out = [6];
    for (let p = this.size - 7; out.length < n; p -= step) out.splice(1, 0, p);
    return out;
  }

  drawFormatBits(mask: number) {
    const data = (LEVEL_M_FORMAT << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const s = this.size;
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(bits, i));
    this.set(8, 7, bit(bits, 6));
    this.set(8, 8, bit(bits, 7));
    this.set(7, 8, bit(bits, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(bits, i));
    for (let i = 0; i < 8; i++) this.set(s - 1 - i, 8, bit(bits, i));
    for (let i = 8; i < 15; i++) this.set(8, s - 15 + i, bit(bits, i));
    this.set(8, s - 8, true); // the dark module
  }

  /** drawCodewords fills the free modules in the standard zigzag. */
  drawCodewords(data: number[]) {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // skip the vertical timing pattern
      for (let v = 0; v < this.size; v++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const up = ((right + 1) & 2) === 0;
          const y = up ? this.size - 1 - v : v;
          if (!this.fixed[y]![x] && i < data.length * 8) {
            this.modules[y]![x] = bit(data[i >>> 3]!, 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  applyMask(mask: number) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.fixed[y]![x]) continue;
        let flip: boolean;
        switch (mask) {
          case 0: flip = (x + y) % 2 === 0; break;
          case 1: flip = y % 2 === 0; break;
          case 2: flip = x % 3 === 0; break;
          case 3: flip = (x + y) % 3 === 0; break;
          case 4: flip = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: flip = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: flip = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: flip = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
        }
        if (flip) this.modules[y]![x] = !this.modules[y]![x];
      }
    }
  }

  /** penalty scores how hard the symbol is to read (lower is better). */
  penalty(): number {
    const s = this.size;
    const m = this.modules;
    let score = 0;
    const lines: boolean[][] = [];
    for (let i = 0; i < s; i++) {
      lines.push(m[i]!);
      lines.push(m.map((row) => row[i]!));
    }
    const finder = [true, false, true, true, true, false, true];
    for (const line of lines) {
      for (let i = 0, run = 1; i < s; i++, run++) {
        if (i + 1 === s || line[i + 1] !== line[i]) {
          if (run >= 5) score += run - 2; // rule 1: 3 for 5 in a row, +1 each
          run = 0;
        }
      }
      for (let i = 0; i + 7 <= s; i++) {
        if (!finder.every((d, k) => line[i + k] === d)) continue;
        const lightBefore = i >= 4 && [1, 2, 3, 4].every((k) => !line[i - k]);
        const lightAfter = i + 11 <= s && [7, 8, 9, 10].every((k) => !line[i + k]);
        if (lightBefore || lightAfter) score += 40; // rule 3
      }
    }
    let dark = 0;
    for (let y = 0; y < s; y++) {
      for (let x = 0; x < s; x++) {
        if (m[y]![x]) dark++;
        if (x + 1 < s && y + 1 < s) {
          const c = m[y]![x];
          if (m[y]![x + 1] === c && m[y + 1]![x] === c && m[y + 1]![x + 1] === c) score += 3; // rule 2
        }
      }
    }
    const total = s * s;
    score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10; // rule 4
    return score;
  }
}

/** qrPath draws the dark modules as one SVG path, offset by margin. */
export function qrPath(m: QrMatrix, margin: number): string {
  let d = "";
  m.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) d += `M${x + margin} ${y + margin}h1v1h-1z`;
    }),
  );
  return d;
}
