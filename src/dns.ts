import { concatBytes, readU16, readU32, writeU16 } from "./binary";

const DNS_HEADER_LENGTH = 12;
const MAX_POINTER_JUMPS = 128;

export class DnsFormatError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "DnsFormatError";
  }
}

export interface DnsName {
  labels: Uint8Array[];
  ruleName: string | null;
  nextOffset: number;
}

export interface DnsQuestion {
  name: DnsName;
  type: number;
  class: number;
  endOffset: number;
}

export interface ResourceRecord {
  start: number;
  end: number;
  type: number;
  class: number;
  ttl: number;
  rdataStart: number;
  rdataEnd: number;
  owner: DnsName;
}

export interface DnsMessageInfo {
  id: number;
  flags: number;
  question: DnsQuestion;
  answerCount: number;
  authorityCount: number;
  additionalCount: number;
  opt: ResourceRecord | null;
  optAdditionalIndex: number;
}

function normalizedRuleLabel(label: Uint8Array): string | null {
  let result = "";
  for (const original of label) {
    let value = original;
    if (value >= 65 && value <= 90) value += 32;
    const allowed =
      (value >= 97 && value <= 122) ||
      (value >= 48 && value <= 57) ||
      value === 45 ||
      value === 95;
    if (!allowed) return null;
    result += String.fromCharCode(value);
  }
  return result;
}

export function parseName(data: Uint8Array, offset: number): DnsName {
  if (offset < 0 || offset >= data.length) {
    throw new DnsFormatError("name_offset_out_of_bounds");
  }

  const labels: Uint8Array[] = [];
  const visitedPointers: number[] = [];
  let cursor = offset;
  let nextOffset = -1;
  let expandedLength = 1;
  let jumps = 0;
  let ruleName: string | null = "";

  while (true) {
    if (cursor >= data.length) {
      throw new DnsFormatError("truncated_name");
    }
    const length = data[cursor] ?? 0;

    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= data.length) {
        throw new DnsFormatError("truncated_pointer");
      }
      const pointer = ((length & 0x3f) << 8) | (data[cursor + 1] ?? 0);
      if (pointer >= data.length) {
        throw new DnsFormatError("pointer_out_of_bounds");
      }
      if (visitedPointers.includes(pointer)) {
        throw new DnsFormatError("pointer_loop");
      }
      visitedPointers.push(pointer);
      jumps += 1;
      if (jumps > MAX_POINTER_JUMPS) {
        throw new DnsFormatError("too_many_pointers");
      }
      if (nextOffset < 0) nextOffset = cursor + 2;
      cursor = pointer;
      continue;
    }

    if ((length & 0xc0) !== 0) {
      throw new DnsFormatError("invalid_label_type");
    }

    cursor += 1;
    if (length === 0) {
      if (nextOffset < 0) nextOffset = cursor;
      break;
    }
    if (length > 63 || cursor + length > data.length) {
      throw new DnsFormatError("invalid_label_length");
    }

    expandedLength += length + 1;
    if (expandedLength > 255) {
      throw new DnsFormatError("name_too_long");
    }

    const label = data.slice(cursor, cursor + length);
    labels.push(label);
    if (ruleName !== null) {
      const normalized = normalizedRuleLabel(label);
      if (normalized === null) {
        ruleName = null;
      } else {
        ruleName = ruleName.length === 0 ? normalized : `${ruleName}.${normalized}`;
      }
    }
    cursor += length;
  }

  return { labels, ruleName, nextOffset };
}

function parseQuestion(data: Uint8Array, offset: number): DnsQuestion {
  const name = parseName(data, offset);
  if (name.nextOffset + 4 > data.length) {
    throw new DnsFormatError("truncated_question");
  }
  return {
    name,
    type: readU16(data, name.nextOffset),
    class: readU16(data, name.nextOffset + 2),
    endOffset: name.nextOffset + 4
  };
}

function parseRecord(data: Uint8Array, offset: number): ResourceRecord {
  const owner = parseName(data, offset);
  if (owner.nextOffset + 10 > data.length) {
    throw new DnsFormatError("truncated_record_header");
  }
  const type = readU16(data, owner.nextOffset);
  const recordClass = readU16(data, owner.nextOffset + 2);
  const ttl = readU32(data, owner.nextOffset + 4);
  const rdLength = readU16(data, owner.nextOffset + 8);
  const rdataStart = owner.nextOffset + 10;
  const rdataEnd = rdataStart + rdLength;
  if (rdataEnd > data.length) {
    throw new DnsFormatError("truncated_rdata");
  }
  return {
    start: offset,
    end: rdataEnd,
    type,
    class: recordClass,
    ttl,
    rdataStart,
    rdataEnd,
    owner
  };
}

export function parseDnsMessage(data: Uint8Array): DnsMessageInfo {
  if (data.length < DNS_HEADER_LENGTH) {
    throw new DnsFormatError("truncated_header");
  }

  const questionCount = readU16(data, 4);
  if (questionCount !== 1) {
    throw new DnsFormatError("question_count_must_be_one");
  }

  const answerCount = readU16(data, 6);
  const authorityCount = readU16(data, 8);
  const additionalCount = readU16(data, 10);
  const question = parseQuestion(data, DNS_HEADER_LENGTH);
  let offset = question.endOffset;

  for (let i = 0; i < answerCount + authorityCount; i += 1) {
    offset = parseRecord(data, offset).end;
  }

  let opt: ResourceRecord | null = null;
  let optAdditionalIndex = -1;
  for (let i = 0; i < additionalCount; i += 1) {
    const record = parseRecord(data, offset);
    if (record.type === 41) {
      if (opt !== null) {
        throw new DnsFormatError("multiple_opt_records");
      }
      if (record.owner.labels.length !== 0) {
        throw new DnsFormatError("opt_owner_must_be_root");
      }
      opt = record;
      optAdditionalIndex = i;
    }
    offset = record.end;
  }

  if (offset !== data.length) {
    throw new DnsFormatError("trailing_bytes");
  }

  return {
    id: readU16(data, 0),
    flags: readU16(data, 2),
    question,
    answerCount,
    authorityCount,
    additionalCount,
    opt,
    optAdditionalIndex
  };
}

export function dnssecDo(info: DnsMessageInfo): boolean {
  return info.opt !== null && (info.opt.ttl & 0x8000) !== 0;
}

function namesEqual(left: DnsName, right: DnsName): boolean {
  if (left.labels.length !== right.labels.length) return false;
  for (let i = 0; i < left.labels.length; i += 1) {
    const a = left.labels[i];
    const b = right.labels[i];
    if (a === undefined || b === undefined || a.length !== b.length) return false;
    for (let j = 0; j < a.length; j += 1) {
      let av = a[j] ?? 0;
      let bv = b[j] ?? 0;
      if (av >= 65 && av <= 90) av += 32;
      if (bv >= 65 && bv <= 90) bv += 32;
      if (av !== bv) return false;
    }
  }
  return true;
}

export function validateUpstreamResponse(
  response: Uint8Array,
  request: DnsMessageInfo
): DnsMessageInfo {
  const parsed = parseDnsMessage(response);
  if ((parsed.flags & 0x8000) === 0) {
    throw new DnsFormatError("upstream_not_a_response");
  }
  if (parsed.id !== request.id) {
    throw new DnsFormatError("transaction_id_mismatch");
  }
  if (
    parsed.question.type !== request.question.type ||
    parsed.question.class !== request.question.class ||
    !namesEqual(parsed.question.name, request.question.name)
  ) {
    throw new DnsFormatError("question_mismatch");
  }
  return parsed;
}

function encodeQuestion(question: DnsQuestion): Uint8Array {
  let length = 1 + 4;
  for (const label of question.name.labels) length += label.length + 1;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const label of question.name.labels) {
    output[offset] = label.length;
    offset += 1;
    output.set(label, offset);
    offset += label.length;
  }
  output[offset] = 0;
  offset += 1;
  writeU16(output, offset, question.type);
  writeU16(output, offset + 2, question.class);
  return output;
}

export function buildDnsError(
  request: Uint8Array,
  rcode: 1 | 2,
  question?: DnsQuestion
): Uint8Array {
  const header = new Uint8Array(DNS_HEADER_LENGTH);
  const id = request.length >= 2 ? readU16(request, 0) : 0;
  const requestFlags = request.length >= 4 ? readU16(request, 2) : 0;
  writeU16(header, 0, id);
  const flags =
    0x8000 |
    (requestFlags & 0x7800) |
    (requestFlags & 0x0110) |
    0x0080 |
    rcode;
  writeU16(header, 2, flags);
  writeU16(header, 4, question === undefined ? 0 : 1);
  if (question === undefined) return header;
  return concatBytes([header, encodeQuestion(question)]);
}
