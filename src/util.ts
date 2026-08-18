import Encoding from "encoding-japanese";

// https://stackoverflow.com/questions/15761790/convert-a-32bit-integer-into-4-bytes-of-data-in-javascript/24947000

export function to_bytes_uint32(num: number): Uint8Array {
  return new Uint8Array([
    num & 0x000000ff,
    (num & 0x0000ff00) >> 8,
    (num & 0x00ff0000) >> 16,
    (num & 0xff000000) >> 24,
  ]);
}

export function from_bytes_uint32(bytes: Uint8Array): number {
  return (
    (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0
  );
}

export function convert_sjis(str: string): Uint8Array {
  // Passing the string directly keeps the intermediate Unicode data in a
  // typed array. encoding-japanese returns a Uint16Array for this mode even
  // though its type declaration says ArrayBuffer.
  const sjisArray = Encoding.convert(str, {
    to: "SJIS",
    from: "UNICODE",
    type: "arraybuffer",
  }) as unknown as Uint16Array;
  return Uint8Array.from(sjisArray);
}

export function uint8array_concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}
