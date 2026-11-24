import { isRecord } from "./decode.js";

/** Resolve an RFC 6901 JSON pointer. undefined when any segment is missing. */
export const resolvePointer = (doc: unknown, pointer: string): unknown =>
  pointer === ""
    ? doc
    : pointer
        .slice(1)
        .split("/")
        .map((s) => s.replaceAll("~1", "/").replaceAll("~0", "~"))
        .reduce<unknown>((node, key) => {
          if (Array.isArray(node)) return node[Number(key)];
          if (isRecord(node)) return node[key];
          return undefined;
        }, doc);
